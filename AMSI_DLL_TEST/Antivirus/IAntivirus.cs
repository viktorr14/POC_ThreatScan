using System.IO;

namespace AMSI_DLL_TEST.Antivirus
{
    public interface IAntivirus
    {
        bool IsMalware(string content, string contentName = "");

        bool IsMalware(byte[] content, string contentName = "");

        bool IsMalware(Stream content, string contentName = "");
    }
}
