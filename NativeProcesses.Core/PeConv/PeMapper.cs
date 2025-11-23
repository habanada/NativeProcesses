using System;
using System.IO;
using System.Runtime.InteropServices;
using NativeProcesses.Core.Inspection;
using NativeProcesses.Core.PE;

namespace NativeProcesses.Core.PeConv
{
	public static class PeMapper
	{
		public static byte[] MapRawToVirtual(byte[] rawFile)
		{
			// Basic Validation
			if (rawFile == null || rawFile.Length < 0x40) return null;

			GCHandle handle = GCHandle.Alloc(rawFile, GCHandleType.Pinned);
			try
			{
				IntPtr rawPtr = handle.AddrOfPinnedObject();

				// 1. DOS Header
				// Wir nutzen die generische Variante <T>, das ist sauberer.
				var dosHeader = Marshal.PtrToStructure<PeHeaders.IMAGE_DOS_HEADER>(rawPtr);

				// FIX: Nutzung der IsValid Property (oder Vergleich mit 0x5A4D), da e_magic jetzt ein ushort ist
				if (!dosHeader.IsValid) return null;

				int ntOffset = dosHeader.e_lfanew;
				// Safety Check: Zeigt NT Header aus der Datei raus?
				if (ntOffset + 264 > rawFile.Length) return null;

				// 2. NT Header Signature
				IntPtr ntPtr = IntPtr.Add(rawPtr, ntOffset);
				uint signature = (uint)Marshal.ReadInt32(ntPtr);
				if (signature != PeHeaders.IMAGE_NT_SIGNATURE) return null;

				// 3. File Header
				IntPtr fileHeaderPtr = IntPtr.Add(ntPtr, 4);
				var fileHeader = Marshal.PtrToStructure<PeHeaders.IMAGE_FILE_HEADER>(fileHeaderPtr);

				// 4. Optional Header
				IntPtr optHeaderPtr = IntPtr.Add(fileHeaderPtr, Marshal.SizeOf<PeHeaders.IMAGE_FILE_HEADER>());
				ushort magic = (ushort)Marshal.ReadInt16(optHeaderPtr);

				uint sizeOfImage = 0;
				uint sizeOfHeaders = 0;

				// Unterscheidung 32/64 Bit für korrekte Sizes
				if (magic == PeHeaders.IMAGE_NT_OPTIONAL_HDR64_MAGIC)
				{
					var opt64 = Marshal.PtrToStructure<PeHeaders.IMAGE_OPTIONAL_HEADER64>(optHeaderPtr);
					sizeOfImage = opt64.SizeOfImage;
					sizeOfHeaders = opt64.SizeOfHeaders;
				}
				else if (magic == PeHeaders.IMAGE_NT_OPTIONAL_HDR32_MAGIC)
				{
					var opt32 = Marshal.PtrToStructure<PeHeaders.IMAGE_OPTIONAL_HEADER32>(optHeaderPtr);
					sizeOfImage = opt32.SizeOfImage;
					sizeOfHeaders = opt32.SizeOfHeaders;
				}
				else
				{
					return null; // Unbekannte Architektur
				}

				// Alloc Virtual Memory Buffer (C# Array)
				byte[] virtualImage = new byte[sizeOfImage];

				// 5. Copy Headers
				// Wir kopieren maximal so viel, wie die Raw-Datei hergibt (falls Header abgeschnitten sind)
				if (sizeOfHeaders > rawFile.Length) sizeOfHeaders = (uint)rawFile.Length;
				Array.Copy(rawFile, 0, virtualImage, 0, sizeOfHeaders);

				// 6. Copy Sections
				// Offset zu den Section Headers berechnen:
				// NT Start + 4 (Sig) + FileHeaderSize + SizeOfOptionalHeader
				int sectionHeadersOffset = ntOffset + 4 + Marshal.SizeOf<PeHeaders.IMAGE_FILE_HEADER>() + fileHeader.SizeOfOptionalHeader;
				int sectionSize = Marshal.SizeOf<PeHeaders.IMAGE_SECTION_HEADER>();

				for (int i = 0; i < fileHeader.NumberOfSections; i++)
				{
					int currentSectionOffset = sectionHeadersOffset + (i * sectionSize);

					// Safety: Nicht über Dateiende lesen
					if (currentSectionOffset + sectionSize > rawFile.Length) break;

					IntPtr sectionPtr = IntPtr.Add(rawPtr, currentSectionOffset);
					var section = Marshal.PtrToStructure<PeHeaders.IMAGE_SECTION_HEADER>(sectionPtr);

					uint dest = section.VirtualAddress;
					uint src = section.PointerToRawData;
					uint rawSize = section.SizeOfRawData;
					uint virtSize = section.VirtualSize;

					// Wenn VirtualSize 0 ist, gilt SizeOfRawData (passiert bei alten Linkern)
					if (virtSize == 0) virtSize = rawSize;

					// Bounds Checks für Destination
					if (dest > sizeOfImage) continue;
					if (dest + rawSize > sizeOfImage) rawSize = sizeOfImage - dest;

					// Kopieren: Nur wenn Raw-Daten existieren (PointerToRawData != 0)
					// BSS Sektionen (uninitialisierte Variablen) haben oft PointerToRawData=0, die bleiben im virtualImage einfach 0x00.
					if (src > 0 && rawSize > 0 && src + rawSize <= rawFile.Length)
					{
						// Wir kopieren das Minimum aus RawSize und VirtualSize, 
						// um nicht in den nächsten Sektionsbereich zu schreiben.
						uint sizeToCopy = Math.Min(rawSize, virtSize);

						Array.Copy(rawFile, (long)src, virtualImage, (long)dest, (long)sizeToCopy);
					}
				}

				return virtualImage;
			}
			catch (Exception)
			{
				return null;
			}
			finally
			{
				if (handle.IsAllocated) handle.Free();
			}
		}

		public static byte[] MapFile(string filePath)
		{
			if (!File.Exists(filePath)) return null;
			try
			{
				byte[] raw = File.ReadAllBytes(filePath);
				return MapRawToVirtual(raw);
			}
			catch
			{
				return null;
			}
		}
	}
}