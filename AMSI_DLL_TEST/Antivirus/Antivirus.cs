using System;
using System.ComponentModel;
using System.IO;

namespace AMSI_DLL_TEST.Antivirus
{
    public class Antivirus : IAntivirus
    {
        private static readonly int FILE_BLOCK_SIZE = 10 * 1024 * 1024; //10MB
        private readonly string applicationName;
        private readonly bool consoleLogging;

        public Antivirus(string applicationName, bool consoleLogging)
        {
            this.applicationName = applicationName;
            this.consoleLogging = consoleLogging;
        }

        public bool IsMalware(string content, string contentName = "")
        {
            IntPtr context = OpenAmsiContextHandle();
            IntPtr session = OpenAmsiSessionHandle(context);

            bool isMalware = ScanString(context, session, content, contentName);

            CloseHandles(context, session);

            return isMalware;
        }

        public bool IsMalware(byte[] content, string contentName = "")
        {
            IntPtr context = OpenAmsiContextHandle();
            IntPtr session = OpenAmsiSessionHandle(context);

            bool isMalware = ScanBuffer(context, session, content, contentName);

            CloseHandles(context, session);

            return isMalware;
        }

        public bool IsMalware(Stream content, string contentName = "")
        {
            IntPtr context = OpenAmsiContextHandle();
            IntPtr session = OpenAmsiSessionHandle(context);

            bool isMalware = ScanStream(context, session, content, contentName);

            CloseHandles(context, session);

            return isMalware;
        }

        private bool ScanString(IntPtr context, IntPtr session, string content, string contentName)
        {
            if (consoleLogging)
                Console.WriteLine($"[SCAN] (string) '{contentName}'; (size) {content.Length}");

            int result = Amsi.ScanString(context, content, contentName, session, out AmsiResult amsiResult);
            if (result != 0)
                throw new Win32Exception(result);

            bool isMalware = Amsi.ResultIsMalware(amsiResult);

            if (consoleLogging)
                Console.WriteLine($"[RESULT] IsMalware = {isMalware.ToString().ToUpper()}\r\n");

            return isMalware;
        }

        private bool ScanBuffer(IntPtr context, IntPtr session, byte[] content, string contentName)
        {
            if (consoleLogging)
                Console.WriteLine($"[SCAN] (bytearray) '{contentName}'; (size) {content.Length}");

            int result = Amsi.ScanBuffer(context, content, (uint)content.Length, contentName, session, out AmsiResult amsiResult);
            if (result != 0)
                throw new Win32Exception(result);

            bool isMalware = Amsi.ResultIsMalware(amsiResult);

            if (consoleLogging)
                Console.WriteLine($"[RESULT] IsMalware = {isMalware.ToString().ToUpper()}\r\n");

            return isMalware;
        }

        private bool ScanStream(IntPtr context, IntPtr session, Stream content, string contentName)
        {
            if (consoleLogging)
                Console.WriteLine($"\r\n[SCAN] (file) '{contentName}'; (size) {content.Length}");

            bool isMalware = false;
            long blocks = 0;

            using (content) {
                long position = 0;
                bool lessThanBlockMaxSize = false;

                do
                {
                    blocks++;

                    lessThanBlockMaxSize = content.Length - position < FILE_BLOCK_SIZE;
                    int readLength = lessThanBlockMaxSize ? (int)(content.Length - position) : FILE_BLOCK_SIZE;
                    string blockName = $"{contentName}_bytes_{position}-{position + readLength - 1}";
                    byte[] chunk = new byte[readLength];

                    content.Read(chunk, 0, readLength);
                    isMalware |= ScanBuffer(context, session, chunk, blockName);

                    position += FILE_BLOCK_SIZE / 2;
                    content.Seek(-FILE_BLOCK_SIZE / 2, SeekOrigin.Current);
                } while (!isMalware && !lessThanBlockMaxSize);

                //double check last chunk when file size bigger than FILE_BLOCK_SIZE and is not multiple of FILE_BLOCK_SIZE / 2 - most cases
                if (content.Length > FILE_BLOCK_SIZE)
                {
                    blocks++;

                    content.Seek(-FILE_BLOCK_SIZE, SeekOrigin.End);

                    string contentChunkName = $"{contentName}_bytes_{content.Length - FILE_BLOCK_SIZE}-{content.Length - 1}";
                    byte[] lastFullChunk = new byte[FILE_BLOCK_SIZE];

                    content.Read(lastFullChunk, 0, FILE_BLOCK_SIZE);
                    isMalware |= ScanBuffer(context, session, lastFullChunk, contentChunkName);
                }
            }

            if (consoleLogging)
                Console.WriteLine($"[CHUNKS] Scanned {blocks} overlapping block of {FILE_BLOCK_SIZE} bytes ({FILE_BLOCK_SIZE / 1024 / 1024} MB) each.\r\n");

            return isMalware;
        }

        #region Amsi Handles

        private IntPtr OpenAmsiContextHandle()
        {
            int result = Amsi.Initialize(applicationName, out IntPtr context);
            if (result != 0)
                throw new Win32Exception(result);

            return context;
        }

        private static IntPtr OpenAmsiSessionHandle(IntPtr context)
        {
            int result = Amsi.OpenSession(context, out IntPtr session);
            if (result != 0)
                throw new Win32Exception(result);

            return session;
        }

        private static void CloseHandles(IntPtr context, IntPtr session)
        {
            Amsi.CloseSession(context, session);
            Amsi.Uninitialize(context);
        }

        #endregion
    }
}