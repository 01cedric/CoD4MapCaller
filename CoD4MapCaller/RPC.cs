using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using PS3Lib;

/// <summary>
/// Runtime-resolved RPC helper for CoD4 PS3.
///
/// Unlike the previous fixed-address build, this class does not require
/// Com_Frame to begin at 0x00162900. It scans the running executable for:
///   - the safe NOP hook inside the client-frame section,
///   - Cbuf_AddText,
///   - the executable SPU printf initialization function used as stub storage.
///
/// Mailbox/scratch workspace:
///   0x12050000 / 0x12051000
///
/// The RPC stub keeps the TOC already present in r2 on the game thread, so it
/// does not hardcode the TOC from a different region/build.
/// </summary>
public sealed class Cod4Rpc : IDisposable
{
    private const uint TextScanStart = 0x00010000;
    private const uint TextScanEndExclusive = 0x00350000;
    private const int ScanReadChunk = 0x10000;

    private const uint DefaultComFrameAddress = 0x00162900;
    private const uint DefaultHookSiteAddress = 0x00162C58;
    private const uint DefaultCbufAddTextAddress = 0x0015EC18;
    private const uint DefaultStubAddress = 0x002D1C98;

    public const uint MailboxAddress = 0x12050000;
    public const uint ScratchAddress = 0x12051000;

    private const int MailboxSize = 0x58;
    private const int ScratchSize = 0x1000;
    private const uint WorkspaceProbeAddress = MailboxAddress + 0x100;
    private const uint TargetAddress = MailboxAddress + 0x4C;
    private const uint IntegerResultAddress = MailboxAddress + 0x50;
    private const uint FloatResultAddress = MailboxAddress + 0x54;

    // The original function at the executable stub location begins with this
    // structural sequence. The TOC-relative displacement in word 3 is masked.
    private static readonly uint[] StubStoragePattern =
    {
        0xF821FF81u, // stdu r1,-0x80(r1)
        0x7C0802A6u, // mflr r0
        0xFBE10078u, // std r31,0x78(r1)
        0x83E20000u, // lwz r31,imm(r2), low 16 bits ignored
        0x39600001u,
        0xF8010090u,
        0x38000002u,
        0x7FE3FB78u,
        0x389F0010u,
        0x901F0010u
    };

    // PowerPC64 big-endian dispatcher assembled for mailbox 0x12050000.
    // It deliberately does not replace r2. Since the hook executes inside the
    // game frame, r2 already contains the correct TOC for the running EBOOT.
    private static readonly byte[] RpcStub =
    {
        0xF8, 0x21, 0xFF, 0x91, 0x7C, 0x08, 0x02, 0xA6,
        0xF8, 0x01, 0x00, 0x80, 0xF8, 0x41, 0x00, 0x28,
        0x3C, 0x60, 0x12, 0x05, 0x60, 0x63, 0x00, 0x00,
        0x81, 0x83, 0x00, 0x4C, 0x2C, 0x0C, 0x00, 0x00,
        0x41, 0x82, 0x00, 0x68, 0x80, 0x83, 0x00, 0x04,
        0x80, 0xA3, 0x00, 0x08, 0x80, 0xC3, 0x00, 0x0C,
        0x80, 0xE3, 0x00, 0x10, 0x81, 0x03, 0x00, 0x14,
        0x81, 0x23, 0x00, 0x18, 0x81, 0x43, 0x00, 0x1C,
        0x81, 0x63, 0x00, 0x20, 0xC0, 0x23, 0x00, 0x24,
        0xC0, 0x43, 0x00, 0x28, 0xC0, 0x63, 0x00, 0x2C,
        0xC0, 0x83, 0x00, 0x30, 0xC0, 0xA3, 0x00, 0x34,
        0xC0, 0xC3, 0x00, 0x38, 0xC0, 0xE3, 0x00, 0x3C,
        0xC1, 0x03, 0x00, 0x40, 0xC1, 0x23, 0x00, 0x48,
        0x80, 0x63, 0x00, 0x00, 0x7D, 0x89, 0x03, 0xA6,
        0x4E, 0x80, 0x04, 0x21, 0x3C, 0x80, 0x12, 0x05,
        0x60, 0x84, 0x00, 0x00, 0x90, 0x64, 0x00, 0x50,
        0x38, 0xA0, 0x00, 0x00, 0x90, 0xA4, 0x00, 0x4C,
        0xE8, 0x41, 0x00, 0x28, 0xE8, 0x01, 0x00, 0x80,
        0x7C, 0x08, 0x03, 0xA6, 0x38, 0x21, 0x00, 0x70,
        0x4E, 0x80, 0x00, 0x20
    };

    private readonly PS3API _ps3;
    private readonly object _sync = new object();

    private uint _hookSiteAddress;
    private uint _stubAddress;
    private uint _cbufAddTextAddress;

    private byte[] _originalHook;
    private byte[] _originalStub;
    private byte[] _originalMailbox;
    private byte[] _originalScratch;

    private bool _enabled;
    private bool _ownsPatch;
    private bool _disposed;

    public Cod4Rpc(PS3API ps3)
    {
        _ps3 = ps3 ?? throw new ArgumentNullException(nameof(ps3));
    }

    public bool IsEnabled => _enabled;
    public uint HookSiteAddress => _hookSiteAddress;
    public uint StubAddress => _stubAddress;
    public uint CbufAddTextAddress => _cbufAddTextAddress;

    /// <summary>
    /// Resolves addresses from the currently running executable and installs
    /// the RPC. No fixed Com_Frame address validation is used.
    /// </summary>
    public void Enable()
    {
        ThrowIfDisposed();

        lock (_sync)
        {
            if (_enabled)
            {
                return;
            }

            byte[] text = ReadRuntimeText();
            ResolveRuntimeAddresses(text);
            ProbeWorkspaceWritable();

            byte[] currentHook = ReadBytes(_hookSiteAddress, 4);

            // Already installed by this exact RPC implementation.
            if (IsBranchLink(currentHook))
            {
                uint branchTarget = DecodeRelativeBranchTarget(_hookSiteAddress, currentHook);
                if (branchTarget == _stubAddress &&
                    BytesEqual(ReadBytes(_stubAddress, RpcStub.Length), RpcStub))
                {
                    _enabled = true;
                    _ownsPatch = false;
                    WaitForIdle(1500);
                    return;
                }

                throw new InvalidOperationException(
                    "The resolved hook instruction is already a branch, but it does not " +
                    "point to this RPC stub. Hook 0x" + _hookSiteAddress.ToString("X8") +
                    " contains " + ToHex(currentHook) + ".");
            }

            if (ReadUInt32BigEndian(currentHook, 0) != 0x60000000u)
            {
                throw new InvalidOperationException(
                    "The resolved hook site is not an original NOP. Address 0x" +
                    _hookSiteAddress.ToString("X8") + " contains " + ToHex(currentHook) + ".");
            }

            byte[] currentStub = ReadBytes(_stubAddress, RpcStub.Length);
            if (!MatchesStubStoragePattern(currentStub, 0) &&
                !BytesEqual(currentStub, RpcStub))
            {
                throw new InvalidOperationException(
                    "The resolved executable stub location is no longer the expected " +
                    "function. Address 0x" + _stubAddress.ToString("X8") +
                    " begins with " + ToHex(Slice(currentStub, 0, Math.Min(40, currentStub.Length))) + ".");
            }

            byte[] mailbox = ReadBytes(MailboxAddress, MailboxSize);
            byte[] scratch = ReadBytes(ScratchAddress, ScratchSize);

            if (!IsAllZero(mailbox) || !IsAllZero(scratch))
            {
                throw new InvalidOperationException(
                    "RPC workspace 0x12050000 is writable but not empty. Refusing to " +
                    "overwrite potentially live data. Mailbox: " + ToHex(mailbox) +
                    "; scratch prefix: " + ToHex(Slice(scratch, 0, 16)) + ".");
            }

            _originalHook = currentHook;
            _originalStub = currentStub;
            _originalMailbox = mailbox;
            _originalScratch = scratch;

            byte[] hookBranch = BuildBranchLink(_hookSiteAddress, _stubAddress);

            // Activate the hook last so the game cannot execute a half-written stub.
            WriteBytes(MailboxAddress, new byte[MailboxSize]);
            WriteBytes(ScratchAddress, new byte[ScratchSize]);
            WriteBytes(_stubAddress, RpcStub);
            WriteBytes(_hookSiteAddress, hookBranch);

            if (!BytesEqual(ReadBytes(_stubAddress, RpcStub.Length), RpcStub) ||
                !BytesEqual(ReadBytes(_hookSiteAddress, 4), hookBranch))
            {
                RestoreNoThrow();
                throw new IOException("RPC patch verification failed after writing memory.");
            }

            _ownsPatch = true;
            _enabled = true;
        }
    }

    public void Disable()
    {
        if (_disposed)
        {
            return;
        }

        lock (_sync)
        {
            if (!_enabled)
            {
                return;
            }

            if (_ownsPatch)
            {
                if (_originalHook != null)
                {
                    WriteBytes(_hookSiteAddress, _originalHook);
                }

                Thread.Sleep(25);

                if (_originalStub != null)
                {
                    WriteBytes(_stubAddress, _originalStub);
                }

                if (_originalMailbox != null)
                {
                    WriteBytes(MailboxAddress, _originalMailbox);
                }

                if (_originalScratch != null)
                {
                    WriteBytes(ScratchAddress, _originalScratch);
                }
            }

            _ownsPatch = false;
            _enabled = false;
        }
    }

    public int Call(uint functionAddress, params object[] parameters)
    {
        ThrowIfDisposed();

        if (!_enabled)
        {
            throw new InvalidOperationException("RPC is not enabled. Call Enable() first.");
        }

        if (functionAddress == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(functionAddress));
        }

        parameters = parameters ?? Array.Empty<object>();

        lock (_sync)
        {
            WaitForIdle(1500);

            WriteBytes(MailboxAddress, new byte[MailboxSize]);
            WriteBytes(ScratchAddress, new byte[ScratchSize]);

            uint gprIndex = 0;
            uint fprIndex = 0;
            bool scratchUsed = false;

            foreach (object parameter in parameters)
            {
                if (parameter == null)
                {
                    WriteGpr(ref gprIndex, 0);
                }
                else if (parameter is int)
                {
                    WriteGpr(ref gprIndex, unchecked((uint)(int)parameter));
                }
                else if (parameter is uint)
                {
                    WriteGpr(ref gprIndex, (uint)parameter);
                }
                else if (parameter is short)
                {
                    WriteGpr(ref gprIndex, unchecked((uint)(int)(short)parameter));
                }
                else if (parameter is ushort)
                {
                    WriteGpr(ref gprIndex, (ushort)parameter);
                }
                else if (parameter is byte)
                {
                    WriteGpr(ref gprIndex, (byte)parameter);
                }
                else if (parameter is sbyte)
                {
                    WriteGpr(ref gprIndex, unchecked((uint)(int)(sbyte)parameter));
                }
                else if (parameter is bool)
                {
                    WriteGpr(ref gprIndex, (bool)parameter ? 1u : 0u);
                }
                else if (parameter is string)
                {
                    if (scratchUsed)
                    {
                        throw new ArgumentException(
                            "Only one string or float[] scratch parameter is supported per call.",
                            nameof(parameters));
                    }

                    WriteScratchString((string)parameter);
                    WriteGpr(ref gprIndex, ScratchAddress);
                    scratchUsed = true;
                }
                else if (parameter is float)
                {
                    WriteFpr(ref fprIndex, (float)parameter);
                }
                else if (parameter is float[])
                {
                    if (scratchUsed)
                    {
                        throw new ArgumentException(
                            "Only one string or float[] scratch parameter is supported per call.",
                            nameof(parameters));
                    }

                    WriteScratchFloats((float[])parameter);
                    WriteGpr(ref gprIndex, ScratchAddress);
                    scratchUsed = true;
                }
                else
                {
                    throw new ArgumentException(
                        "Unsupported RPC parameter type: " + parameter.GetType().FullName,
                        nameof(parameters));
                }
            }

            WriteUInt32(IntegerResultAddress, 0);
            WriteUInt32(FloatResultAddress, 0);

            // Publish the target last.
            WriteUInt32(TargetAddress, functionAddress);

            try
            {
                WaitForIdle(1500);
            }
            catch
            {
                WriteUInt32(TargetAddress, 0);
                throw;
            }

            return ReadInt32(IntegerResultAddress);
        }
    }

    public void CallVoid(uint functionAddress, params object[] parameters)
    {
        Call(functionAddress, parameters);
    }

    public float ReadLastFloatResult()
    {
        byte[] bytes = ReadBytes(FloatResultAddress, 4);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes);
        }

        return BitConverter.ToSingle(bytes, 0);
    }

    public void ExecuteCommand(string command, int localClientNum = 0)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            throw new ArgumentException("Command is empty.", nameof(command));
        }

        string normalized = command.EndsWith("\n", StringComparison.Ordinal)
            ? command
            : command + "\n";

        CallVoid(_cbufAddTextAddress, localClientNum, normalized);
    }

    public void ChangeMap(string mapName, int localClientNum = 0)
    {
        if (string.IsNullOrWhiteSpace(mapName))
        {
            throw new ArgumentException("Map name is empty.", nameof(mapName));
        }

        string clean = mapName.Trim();
        if (clean.IndexOfAny(new[] { '\r', '\n', ';', '"' }) >= 0)
        {
            throw new ArgumentException("Map name contains invalid command characters.", nameof(mapName));
        }

        ExecuteCommand("map " + clean, localClientNum);
    }

    public void RestartMap(int localClientNum = 0)
    {
        ExecuteCommand("map_restart", localClientNum);
    }

    /// <summary>
    /// Returns runtime bytes and the addresses found by the signature resolver.
    /// This does not patch memory.
    /// </summary>
    public string GetDiagnostics()
    {
        ThrowIfDisposed();

        StringBuilder output = new StringBuilder();
        output.AppendLine("Default Com_Frame 0x00162900: " +
                          ToHex(ReadBytes(DefaultComFrameAddress, 16)));
        output.AppendLine("Default hook 0x00162C58: " +
                          ToHex(ReadBytes(DefaultHookSiteAddress, 16)));
        output.AppendLine("Default Cbuf_AddText 0x0015EC18: " +
                          ToHex(ReadBytes(DefaultCbufAddTextAddress, 16)));
        output.AppendLine("Default stub 0x002D1C98: " +
                          ToHex(ReadBytes(DefaultStubAddress, 16)));
        output.AppendLine("Mailbox 0x12050000: " +
                          ToHex(ReadBytes(MailboxAddress, 16)));

        try
        {
            byte[] text = ReadRuntimeText();
            List<uint> hooks = FindHookCandidates(text);
            List<uint> cbufs = FindCbufCandidates(text);
            List<uint> stubs = FindStubStorageCandidates(text);

            output.AppendLine("Hook candidates: " + FormatAddresses(hooks));
            output.AppendLine("Cbuf_AddText candidates: " + FormatAddresses(cbufs));
            output.AppendLine("Stub-storage candidates: " + FormatAddresses(stubs));
        }
        catch (Exception ex)
        {
            output.AppendLine("Runtime scan failed: " + ex.Message);
        }

        return output.ToString();
    }

    /// <summary>
    /// Dumps the scanned runtime text range to a PC file. This is useful when
    /// the signatures do not exist in a heavily modified or different EBOOT.
    /// </summary>
    public void DumpRuntimeText(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Output path is empty.", nameof(path));
        }

        File.WriteAllBytes(path, ReadRuntimeText());
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        try
        {
            Disable();
        }
        finally
        {
            _disposed = true;
        }
    }

    private void ResolveRuntimeAddresses(byte[] text)
    {
        List<uint> hookCandidates = FindHookCandidates(text);
        List<uint> cbufCandidates = FindCbufCandidates(text);
        List<uint> stubCandidates = FindStubStorageCandidates(text);

        if (hookCandidates.Count != 1 ||
            cbufCandidates.Count != 1 ||
            stubCandidates.Count != 1)
        {
            throw new InvalidOperationException(
                "The running EBOOT could not be resolved safely. " +
                "Hook candidates: " + FormatAddresses(hookCandidates) + "; " +
                "Cbuf_AddText candidates: " + FormatAddresses(cbufCandidates) + "; " +
                "stub candidates: " + FormatAddresses(stubCandidates) + ". " +
                "Do not bypass this check. Use DumpRuntimeText(...) and analyze the " +
                "actual running executable if a candidate count is not exactly one.");
        }

        _hookSiteAddress = hookCandidates[0];
        _cbufAddTextAddress = cbufCandidates[0];
        _stubAddress = stubCandidates[0];

        if (RpcStub.Length > 0x138)
        {
            throw new InvalidOperationException(
                "Internal RPC stub is larger than the verified 0x138-byte storage function.");
        }
    }

    private byte[] ReadRuntimeText()
    {
        int length = checked((int)(TextScanEndExclusive - TextScanStart));
        byte[] output = new byte[length];

        for (int offset = 0; offset < length; offset += ScanReadChunk)
        {
            int count = Math.Min(ScanReadChunk, length - offset);
            byte[] block = ReadBytes(TextScanStart + (uint)offset, count);
            Buffer.BlockCopy(block, 0, output, offset, count);
        }

        return output;
    }

    private static List<uint> FindHookCandidates(byte[] text)
    {
        List<uint> matches = new List<uint>();

        // Structural sequence around the original NOP:
        //   li r3,0
        //   mr r4,r28
        //   bl ...
        //   nop             <- hook
        //   bl ...
        //   extsw r29,r31
        //   mr r3,r29
        //   bl ...
        //   nop
        for (int offset = 0; offset <= text.Length - 36; offset += 4)
        {
            uint w0 = ReadUInt32BigEndian(text, offset + 0x00);
            uint w1 = ReadUInt32BigEndian(text, offset + 0x04);
            uint w2 = ReadUInt32BigEndian(text, offset + 0x08);
            uint w3 = ReadUInt32BigEndian(text, offset + 0x0C);
            uint w4 = ReadUInt32BigEndian(text, offset + 0x10);
            uint w5 = ReadUInt32BigEndian(text, offset + 0x14);
            uint w6 = ReadUInt32BigEndian(text, offset + 0x18);
            uint w7 = ReadUInt32BigEndian(text, offset + 0x1C);
            uint w8 = ReadUInt32BigEndian(text, offset + 0x20);

            bool hookWordAcceptable = w3 == 0x60000000u || IsBranchLinkInstruction(w3);

            if (w0 == 0x38600000u &&
                w1 == 0x7F84E378u &&
                IsBranchLinkInstruction(w2) &&
                hookWordAcceptable &&
                IsBranchLinkInstruction(w4) &&
                w5 == 0x7FFD07B4u &&
                w6 == 0x7FA3EB78u &&
                IsBranchLinkInstruction(w7) &&
                w8 == 0x60000000u)
            {
                matches.Add(TextScanStart + (uint)offset + 0x0C);
            }
        }

        return matches;
    }

    private static List<uint> FindCbufCandidates(byte[] text)
    {
        List<uint> matches = new List<uint>();

        for (int offset = 0; offset <= text.Length - 76; offset += 4)
        {
            uint[] w = new uint[19];
            for (int i = 0; i < w.Length; i++)
            {
                w[i] = ReadUInt32BigEndian(text, offset + (i * 4));
            }

            if (w[0] == 0xF821FF81u &&
                w[1] == 0x7C0802A6u &&
                w[2] == 0xFBC10070u &&
                w[3] == 0xFBE10078u &&
                w[4] == 0x7C7E1B78u &&
                w[5] == 0x7C9F2378u &&
                w[6] == 0x3860001Fu &&
                w[7] == 0xF8010090u &&
                IsBranchInstruction(w[8]) &&
                w[9] == 0x60000000u &&
                w[10] == 0x7BEA0020u &&
                w[11] == 0x880A0000u &&
                w[12] == 0x7C000774u &&
                w[13] == 0x2F800070u &&
                IsConditionalBranchInstruction(w[14]) &&
                w[15] == 0x2F800050u &&
                IsConditionalBranchInstruction(w[16]) &&
                w[17] == 0x894A0000u &&
                w[18] == 0x57C02036u)
            {
                matches.Add(TextScanStart + (uint)offset);
            }
        }

        return matches;
    }

    private static List<uint> FindStubStorageCandidates(byte[] text)
    {
        List<uint> matches = new List<uint>();

        for (int offset = 0; offset <= text.Length - 40; offset += 4)
        {
            if (MatchesStubStoragePattern(text, offset))
            {
                matches.Add(TextScanStart + (uint)offset);
            }
        }

        return matches;
    }

    private static bool MatchesStubStoragePattern(byte[] bytes, int offset)
    {
        if (bytes == null || offset < 0 || offset + (StubStoragePattern.Length * 4) > bytes.Length)
        {
            return false;
        }

        for (int i = 0; i < StubStoragePattern.Length; i++)
        {
            uint actual = ReadUInt32BigEndian(bytes, offset + (i * 4));
            uint expected = StubStoragePattern[i];

            if (i == 3)
            {
                if ((actual & 0xFFFF0000u) != expected)
                {
                    return false;
                }
            }
            else if (actual != expected)
            {
                return false;
            }
        }

        return true;
    }

    private void WriteGpr(ref uint index, uint value)
    {
        if (index >= 9)
        {
            throw new ArgumentException("RPC supports only r3 through r11.");
        }

        WriteUInt32(MailboxAddress + (index * 4), value);
        index++;
    }

    private void WriteFpr(ref uint index, float value)
    {
        if (index >= 9)
        {
            throw new ArgumentException("RPC supports only f1 through f9.");
        }

        uint offset = index < 8
            ? 0x24u + (index * 4u)
            : 0x48u;

        WriteSingle(MailboxAddress + offset, value);
        index++;
    }

    private void WriteScratchString(string value)
    {
        byte[] bytes = Encoding.ASCII.GetBytes(value + "\0");
        if (bytes.Length > ScratchSize)
        {
            throw new ArgumentException(
                "RPC string exceeds " + (ScratchSize - 1) + " ASCII characters.");
        }

        WriteBytes(ScratchAddress, new byte[ScratchSize]);
        WriteBytes(ScratchAddress, bytes);
    }

    private void WriteScratchFloats(float[] values)
    {
        if (values == null)
        {
            throw new ArgumentNullException(nameof(values));
        }

        int byteCount = checked(values.Length * 4);
        if (byteCount > ScratchSize)
        {
            throw new ArgumentException(
                "Float array exceeds " + (ScratchSize / 4) + " elements.");
        }

        byte[] output = new byte[byteCount];
        for (int i = 0; i < values.Length; i++)
        {
            byte[] value = BitConverter.GetBytes(values[i]);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(value);
            }

            Buffer.BlockCopy(value, 0, output, i * 4, 4);
        }

        WriteBytes(ScratchAddress, new byte[ScratchSize]);
        WriteBytes(ScratchAddress, output);
    }

    private void ProbeWorkspaceWritable()
    {
        byte[] original = ReadBytes(WorkspaceProbeAddress, 4);
        byte[] probe = { 0x43, 0x4F, 0x44, 0x34 };

        try
        {
            WriteBytes(WorkspaceProbeAddress, probe);
            byte[] readBack = ReadBytes(WorkspaceProbeAddress, probe.Length);
            if (!BytesEqual(readBack, probe))
            {
                throw new IOException(
                    "0x12050000 is readable but not writable through the current PS3 API.");
            }
        }
        finally
        {
            WriteBytes(WorkspaceProbeAddress, original);
        }
    }

    private void WaitForIdle(int timeoutMilliseconds)
    {
        Stopwatch stopwatch = Stopwatch.StartNew();

        while (ReadUInt32(TargetAddress) != 0)
        {
            if (stopwatch.ElapsedMilliseconds >= timeoutMilliseconds)
            {
                throw new TimeoutException(
                    "RPC timed out. The hook did not execute, or the target function did not return.");
            }

            Thread.Sleep(1);
        }
    }

    private static byte[] BuildBranchLink(uint sourceAddress, uint targetAddress)
    {
        long displacement = (long)targetAddress - sourceAddress;

        if ((displacement & 3) != 0)
        {
            throw new ArgumentException("PowerPC branch target is not four-byte aligned.");
        }

        if (displacement < -0x02000000L || displacement > 0x01FFFFFCL)
        {
            throw new ArgumentOutOfRangeException(
                nameof(targetAddress),
                "PowerPC relative branch target is outside the +/-32 MB range.");
        }

        uint instruction = 0x48000001u | (unchecked((uint)displacement) & 0x03FFFFFCu);
        return UInt32ToBigEndian(instruction);
    }

    private static bool IsBranchInstruction(uint instruction)
    {
        return (instruction & 0xFC000000u) == 0x48000000u;
    }

    private static bool IsBranchLinkInstruction(uint instruction)
    {
        return (instruction & 0xFC000003u) == 0x48000001u;
    }

    private static bool IsConditionalBranchInstruction(uint instruction)
    {
        return (instruction & 0xFC000000u) == 0x40000000u;
    }

    private static bool IsBranchLink(byte[] instruction)
    {
        return instruction != null &&
               instruction.Length == 4 &&
               IsBranchLinkInstruction(ReadUInt32BigEndian(instruction, 0));
    }

    private static uint DecodeRelativeBranchTarget(uint sourceAddress, byte[] instructionBytes)
    {
        uint instruction = ReadUInt32BigEndian(instructionBytes, 0);
        int displacement = unchecked((int)(instruction & 0x03FFFFFCu));

        if ((displacement & 0x02000000) != 0)
        {
            displacement |= unchecked((int)0xFC000000u);
        }

        return unchecked(sourceAddress + (uint)displacement);
    }

    private void WriteUInt32(uint address, uint value)
    {
        WriteBytes(address, UInt32ToBigEndian(value));
    }

    private void WriteSingle(uint address, float value)
    {
        byte[] bytes = BitConverter.GetBytes(value);
        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(bytes);
        }

        WriteBytes(address, bytes);
    }

    private uint ReadUInt32(uint address)
    {
        return ReadUInt32BigEndian(ReadBytes(address, 4), 0);
    }

    private int ReadInt32(uint address)
    {
        return unchecked((int)ReadUInt32(address));
    }

    private static uint ReadUInt32BigEndian(byte[] bytes, int offset)
    {
        return ((uint)bytes[offset] << 24) |
               ((uint)bytes[offset + 1] << 16) |
               ((uint)bytes[offset + 2] << 8) |
               bytes[offset + 3];
    }

    private static byte[] UInt32ToBigEndian(uint value)
    {
        return new[]
        {
            (byte)(value >> 24),
            (byte)(value >> 16),
            (byte)(value >> 8),
            (byte)value
        };
    }

    private byte[] ReadBytes(uint address, int length)
    {
        byte[] bytes = _ps3.GetBytes(address, length);
        if (bytes == null || bytes.Length != length)
        {
            throw new IOException(
                "Failed to read " + length + " bytes from 0x" + address.ToString("X8") + ".");
        }

        return bytes;
    }

    private void WriteBytes(uint address, byte[] bytes)
    {
        if (bytes == null)
        {
            throw new ArgumentNullException(nameof(bytes));
        }

        _ps3.SetMemory(address, bytes);
    }

    private void RestoreNoThrow()
    {
        try
        {
            if (_originalHook != null && _hookSiteAddress != 0)
            {
                WriteBytes(_hookSiteAddress, _originalHook);
            }

            if (_originalStub != null && _stubAddress != 0)
            {
                WriteBytes(_stubAddress, _originalStub);
            }

            if (_originalMailbox != null)
            {
                WriteBytes(MailboxAddress, _originalMailbox);
            }

            if (_originalScratch != null)
            {
                WriteBytes(ScratchAddress, _originalScratch);
            }
        }
        catch
        {
            // Preserve the original installation exception.
        }
    }

    private static byte[] Slice(byte[] source, int offset, int length)
    {
        byte[] result = new byte[length];
        Buffer.BlockCopy(source, offset, result, 0, length);
        return result;
    }

    private static string FormatAddresses(List<uint> addresses)
    {
        if (addresses == null || addresses.Count == 0)
        {
            return "none";
        }

        StringBuilder output = new StringBuilder();
        for (int i = 0; i < addresses.Count; i++)
        {
            if (i != 0)
            {
                output.Append(", ");
            }

            output.Append("0x");
            output.Append(addresses[i].ToString("X8"));
        }

        return output.ToString();
    }

    private static string ToHex(byte[] bytes)
    {
        if (bytes == null)
        {
            return "<null>";
        }

        StringBuilder output = new StringBuilder(bytes.Length * 3);
        for (int i = 0; i < bytes.Length; i++)
        {
            if (i != 0)
            {
                output.Append(' ');
            }

            output.Append(bytes[i].ToString("X2"));
        }

        return output.ToString();
    }

    private static bool BytesEqual(byte[] left, byte[] right)
    {
        if (ReferenceEquals(left, right))
        {
            return true;
        }

        if (left == null || right == null || left.Length != right.Length)
        {
            return false;
        }

        for (int i = 0; i < left.Length; i++)
        {
            if (left[i] != right[i])
            {
                return false;
            }
        }

        return true;
    }

    private static bool IsAllZero(byte[] bytes)
    {
        if (bytes == null)
        {
            return false;
        }

        for (int i = 0; i < bytes.Length; i++)
        {
            if (bytes[i] != 0)
            {
                return false;
            }
        }

        return true;
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(Cod4Rpc));
        }
    }
}