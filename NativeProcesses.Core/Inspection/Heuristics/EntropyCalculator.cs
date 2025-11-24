/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using System;
using System.Collections.Generic;

namespace NativeProcesses.Core.Inspection.Heuristics
{
    public static class EntropyCalculator
    {
        public static double Calculate(byte[] data, int length)
        {
            if (data == null || length == 0) return 0.0;

            int[] frequency = new int[256];
            for (int i = 0; i < length; i++)
            {
                frequency[data[i]]++;
            }

            double entropy = 0.0;
            double len = (double)length;

            for (int i = 0; i < 256; i++)
            {
                if (frequency[i] > 0)
                {
                    double p = (double)frequency[i] / len;
                    entropy -= p * Math.Log(p, 2);
                }
            }

            return entropy;
        }
    }
}