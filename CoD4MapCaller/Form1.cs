using PS3Lib;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.TextBox;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.TreeView;

namespace CoD4MapCaller
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private PS3API PS3 = new PS3API();
        private Cod4Rpc _rpc;

        private void EnableRpc()
        {
            _rpc = new Cod4Rpc(PS3);
            _rpc.Enable();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            PS3.ConnectTarget();
            PS3.AttachProcess();
        }


        private void button2_Click(object sender, EventArgs e)
        {
            EnableRpc();
            _rpc.ExecuteCommand("ui_mapname " + textBox1.Text + "\n");
            _rpc?.Dispose();
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }

        private void button3_Click(object sender, EventArgs e)
        {
            _rpc.ChangeMap(textBox1.Text + "\n");
        }

        private void button4_Click(object sender, EventArgs e)
        {
            PS3.CCAPI.ConnectTarget();
            PS3.CCAPI.AttachProcess();
        }
    }
}
