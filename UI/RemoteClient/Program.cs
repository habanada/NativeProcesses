/*

 ██████   █████            █████     ███                       ███████████                                                                       
░░██████ ░░███            ░░███     ░░░                       ░░███░░░░░███                                                                      
 ░███░███ ░███   ██████   ███████   ████  █████ █████  ██████  ░███    ░███ ████████   ██████   ██████   ██████   █████   █████   ██████   █████ 
 ░███░░███░███  ░░░░░███ ░░░███░   ░░███ ░░███ ░░███  ███░░███ ░██████████ ░░███░░███ ███░░███ ███░░███ ███░░███ ███░░   ███░░   ███░░███ ███░░  
 ░███ ░░██████   ███████   ░███     ░███  ░███  ░███ ░███████  ░███░░░░░░   ░███ ░░░ ░███ ░███░███ ░░░ ░███████ ░░█████ ░░█████ ░███████ ░░█████ 
 ░███  ░░█████  ███░░███   ░███ ███ ░███  ░░███ ███  ░███░░░   ░███         ░███     ░███ ░███░███  ███░███░░░   ░░░░███ ░░░░███░███░░░   ░░░░███
 █████  ░░█████░░████████  ░░█████  █████  ░░█████   ░░██████  █████        █████    ░░██████ ░░██████ ░░██████  ██████  ██████ ░░██████  ██████ 
░░░░░    ░░░░░  ░░░░░░░░    ░░░░░  ░░░░░    ░░░░░     ░░░░░░  ░░░░░        ░░░░░      ░░░░░░   ░░░░░░   ░░░░░░  ░░░░░░  ░░░░░░   ░░░░░░  ░░░░░░  
                                                                                                                            
 *  NativeProcesses Framework
 *  High-performance Windows process monitoring and control library
 *  Copyright (C) 2025  Selahattin Erkoc
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 *  --------------------------------------------------------------
 *  Summary:
 *  Internal and educational use is permitted, including modification
 *  and private distribution. Public distribution of binaries must
 *  include full corresponding source code under the same license.
 *  --------------------------------------------------------------
 */
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
            Application.Run(new RemoteClientForm());
        }
    }
}
