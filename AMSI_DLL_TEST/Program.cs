using AMSI_DLL_TEST.Antivirus;
using System;
using System.IO;
using System.Text;

namespace AV_PoC_WindowsDefender_DLL
{
    class Program
    {
        private static readonly string HARMFUL_EICAR_RAW_68BYTE_STRING_NAME = "<harmful> (string) EICAR 68-byte";
        private static readonly string HARMFUL_EICAR_RAW_68BYTE_BYTEARRAY_NAME = "<harmful> (bytearray) EICAR 68-byte";
        private static readonly string HARMFUL_EICAR_RAW_128BYTE_STRING_NAME = "<harmful> (string) EICAR 128-byte";
        private static readonly string HARMFUL_EICAR_RAW_128BYTE_BYTEARRAY_NAME = "<harmful> (bytearray) EICAR 128-byte";
        private static readonly string HARMLESS_EICAR_RAW_OVER128BYTE_STRING_NAME = "<harmless> (string) EICAR over-128-byte";
        private static readonly string HARMLESS_EICAR_RAW_OVER128BYTE_BYTEARRAY_NAME = "<harmless> (bytearray) EICAR over-128-byte";
        private static readonly string HARMLESS_PLAIN_STRING_NAME = "<harmless> (string) PLAIN";
        private static readonly string HARMLESS_PLAIN_BYTEARRAY_NAME = "<harmless> (bytearray) PLAIN";

        private static readonly string SMALL_EXE_FILE_NAME = "C:/AV_Test/small_executable.exe";
        private static readonly string SMALL_PDF_FILE_NAME = "C:/AV_Test/small_pdf.pdf";
        private static readonly string LARGE_DATA_FILE_NAME = "C:/AV_Test/large_data_file.MPQ";

        private static readonly string WHITESPACE_UP_TO_128BYTE_SUFFIX_CONTENT = "                                                            ";
        private static readonly string WHITESPACE_OVER_128BYTE_SUFFIX_SUPPLEMENT_CONTENT = " ";
        private static readonly string HARMFUL_EICAR_RAW_68BYTE_STRING_CONTENT = @"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

        static void Main(string[] args)
        {
            ReadySetGo();

            Antivirus antivirus = new("appName", true);

            (string, object)[] stringAndByteArrayContent = new (string, object)[]
            {
                new (HARMFUL_EICAR_RAW_68BYTE_STRING_NAME, HARMFUL_EICAR_RAW_68BYTE_STRING_CONTENT),
                new (HARMFUL_EICAR_RAW_68BYTE_BYTEARRAY_NAME, Encoding.ASCII.GetBytes(HARMFUL_EICAR_RAW_68BYTE_STRING_CONTENT)),
                new (HARMFUL_EICAR_RAW_128BYTE_STRING_NAME, $"{HARMFUL_EICAR_RAW_68BYTE_STRING_CONTENT}{WHITESPACE_UP_TO_128BYTE_SUFFIX_CONTENT}"),
                new (HARMFUL_EICAR_RAW_128BYTE_BYTEARRAY_NAME, Encoding.ASCII.GetBytes($"{HARMFUL_EICAR_RAW_68BYTE_STRING_CONTENT}{WHITESPACE_UP_TO_128BYTE_SUFFIX_CONTENT}")),
                new (HARMLESS_EICAR_RAW_OVER128BYTE_STRING_NAME, $"{HARMFUL_EICAR_RAW_68BYTE_STRING_CONTENT}{WHITESPACE_UP_TO_128BYTE_SUFFIX_CONTENT}{WHITESPACE_OVER_128BYTE_SUFFIX_SUPPLEMENT_CONTENT}"),
                new (HARMLESS_EICAR_RAW_OVER128BYTE_BYTEARRAY_NAME, Encoding.ASCII.GetBytes($"{HARMFUL_EICAR_RAW_68BYTE_STRING_CONTENT}{WHITESPACE_UP_TO_128BYTE_SUFFIX_CONTENT}{WHITESPACE_OVER_128BYTE_SUFFIX_SUPPLEMENT_CONTENT}")),
                new (HARMLESS_PLAIN_STRING_NAME, WHITESPACE_UP_TO_128BYTE_SUFFIX_CONTENT),
                new (HARMLESS_PLAIN_BYTEARRAY_NAME, Encoding.ASCII.GetBytes(WHITESPACE_UP_TO_128BYTE_SUFFIX_CONTENT))
            };

            int scans = 0;
            int threats = 0;
            bool result;

            foreach ((string name, object content) in stringAndByteArrayContent)
            {
                scans++;

                if (content.GetType() == typeof(string))
                    result = antivirus.IsMalware(content as string, name);
                else if (content.GetType() == typeof(byte[]))
                    result = antivirus.IsMalware(content as byte[], name);
                else
                    throw new NotImplementedException();

                if (result)
                    threats++;

                Console.ReadKey();
            }

            string[] files = new string[] {
                SMALL_EXE_FILE_NAME,
                SMALL_PDF_FILE_NAME,
                LARGE_DATA_FILE_NAME
            };

            foreach (string fileName in files)
            {
                FileStream file = File.OpenRead(fileName);

                scans++;

                result = antivirus.IsMalware(file, fileName);
                if (result)
                    threats++;

                Console.ReadKey();
            }

            Console.WriteLine($"SCANS: {scans}; THREATS: {threats}");
        }

        private static void ReadySetGo()
        {
            Console.WriteLine("Ready...");
            Console.ReadKey();
            Console.WriteLine("Set...");
            Console.ReadKey();
            Console.WriteLine("GO!");
            Console.ReadKey();
            Console.WriteLine();
        }
    }
}