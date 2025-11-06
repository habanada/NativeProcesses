// ------------------------------------------------------------
// NativeProcesses
// Copyright (c) 2025 Selahattin Erkoc
// Licensed under the MIT License (for non-commercial use).
// Commercial support available at: nativeprocesses@protonmail.com
// ------------------------------------------------------------



//### 🧾 License
//This project is licensed under the **MIT Non-Commercial License**.  
//You may freely use and modify the code for personal, educational, and research purposes.

//For **commercial or enterprise usage**, please consider supporting development  
//via a donation or commercial license.

//👉 [Buy me a Coffee](https://www.buymeacoffee.com/selahattin)  
//📧 Contact: nativeprocesses @protonmail.com


/*
 ## ☕ Support the Developer

If you use **NativeProcesses** in your projects and want to say thank you:  
You can support my work in two ways:

- 💸 Donate via [Buy Me a Coffee](https://www.buymeacoffee.com/selahattin)  
- 🎁 Send an **Amazon Gift Card** to: **nativeprocesses@protonmail.com**

Every contribution helps keep development active and free for the community 💙

 * */

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
