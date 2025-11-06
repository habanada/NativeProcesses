// ------------------------------------------------------------
// NativeProcesses
// Copyright (c) 2025 Selahattin Erkoc
// Licensed under the MIT License (for non-commercial use).
// Commercial support available at: nativeprocesses@protonmail.com
// ------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace ProcessDemo
{
    static class Program
    {
        /// <summary>
        /// Der Haupteinstiegspunkt für die Anwendung.
        /// </summary>
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
    }
}
