using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Net.Sockets;
using System.Reflection.Metadata;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using PCSC;
using PCSC.Iso7816;


namespace Mifare1kTest {
    public class Program {
        private static readonly byte[] DATA_TO_WRITE = {
            0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
        };

        private const byte MSB = 0x00;
        private const byte LSB = 0x08;

        public static void Main() {
            using (var context = ContextFactory.Instance.Establish(SCardScope.System)) {
               // getTckn();
               selectMF();
               // selectDF("3D10");
               getCertificate();
                string[] namesurname = getNameSurname();
            
                string tc = getTckn();
                Console.WriteLine(namesurname[0]+" "+ namesurname[1]);
                Console.WriteLine(tc.ToString());
            }

            Console.ReadKey();
        }

        /// <summary>
        /// Asks the user to select a smart-card reader containing the Mifare chip
        /// </summary>
        /// <param name="readerNames">Collection of available smart-card readers</param>
        /// <returns>The selected reader name or <c>null</c> if none</returns>
        private static string ChooseReader(IList<string> readerNames) {
            Console.WriteLine(new string('=', 79));
            Console.WriteLine("WARNING!! This will overwrite data in MSB {0:X2} LSB {1:X2} using the default key.", MSB,
                LSB);
            Console.WriteLine(new string('=', 79));

            // Show available readers.
            Console.WriteLine("Available readers: ");
            for (var i = 0; i < readerNames.Count; i++) {
                Console.WriteLine($"[{i}] {readerNames[i]}");
            }

            // Ask the user which one to choose.
            Console.Write("Which reader has an inserted Mifare 1k/4k card? ");

            var line = Console.ReadLine();

            if (int.TryParse(line, out var choice) && (choice >= 0) && (choice <= readerNames.Count)) {
                return readerNames[choice];
            }

            Console.WriteLine("An invalid number has been entered.");
            Console.ReadKey();

            return null;
        }

        public static void ValidateCertificate(byte[] CertToValidateData, byte[] IssuerCertData, out byte[] ServiceResponse, out bool IsError, out DateTime LastOcsp)
        {
            IsError = false;
            ServiceResponse = null;
            LastOcsp =
        DateTime.Today
        ;
            OcspClient d = new OcspClient();
            //try
            //{
            //    OcspClient ocspClient = new OcspClient();
            //    X509Certificate eeCert = CertificateUtils.LoadCertificate(CertToValidateData);
            //    X509Certificate issuerCert = CertificateUtils.LoadCertificate(IssuerCertData);
            //    return ocspClient.Query(eeCert, issuerCert, out ServiceResponse);
            //}
            //catch (Exception ex)
            //{
            //    CisdupManager.EvException?.Invoke(ClassName, "ValidateCertificate", ex);
            //    IsError = true;
            //    return CertificateStatus.Unknown;
            //}
        }
        private static bool IsEmpty(ICollection<string> readerNames) =>
            readerNames == null || readerNames.Count < 1;

        public static string getTckn() {
           byte[] fileID = { 0x3D, 0x10, 0x3D, 0x20, 0x2F, 0x10 };
        //   byte[] fileId = { 0x3D, 0x10, 0x2F, 0x04 };
            selectFile(fileID);
            byte[] byteReadData = ReadBinary();

            return Encoding.UTF8.GetString(byteReadData, 0, byteReadData.Length).Substring(4, 11);
        }

        public static byte[] ReadBinary() {
            try {
                var ctx = ContextFactory.Instance.Establish(SCardScope.System);
                var firstReader = ctx.GetReaders().FirstOrDefault();

                var isoReader = new IsoReader(
                context: ctx,
                readerName: firstReader,
                mode: SCardShareMode.Shared,
                protocol: SCardProtocol.Any,
                releaseContextOnDispose: false);

                byte[] dataBuffer = { 0xF4 };

                var apdu = new CommandApdu(IsoCase.Case2Short, isoReader.ActiveProtocol) {
                    CLA = 0x00, // Class
                    Instruction = (InstructionCode)0xB0,
                    P1 = 0x00,// Parameter 1
                    P2 = 0x00, // Parameter 2
                    Le = 0xF4 // Expected length of the returned data

                };


                var response = isoReader.Transmit(apdu);

                if (!response.HasData) {
                    string aaa = "Error on APDU Command" + " " + "0x" + response.StatusWord.ToString("X");

                    return null;

                } else {

                    string aaa = BitConverter.ToString(response.GetData());

                    return response.GetData();
                }

            } catch (Exception ex) {

                return null;

            }

            // Build a GET CHALLENGE command 

        }


        private void Button5_Click(object sender, EventArgs e) {
            string[] data = getNameSurname();

           string tc = getTckn();
            string ad = data[0];
            string soyad = data[1];
        }

        public static void getCertificate()
        {


            byte[] fileId = { 0x3D, 0x00, 0x2F, 0x10 };

            var response = selectFile(fileId);

            var fileSize = new byte[2];

            Array.Copy(response, 4, fileSize, 0, fileSize.Length);
            Array.Reverse(fileSize);
            var size = BitConverter.ToInt16(fileSize, 0);

            byte[] CertificateRawHeader = new byte[size];

            if (size != 0)
            {
                int PacketSize = 230;

                int packetCount = size / PacketSize;
                int lastPacketSize = size % PacketSize;
                byte packetOrder = 0x00;

                for (int i = 0; i < packetCount; i++)
                {
                    if (i < 2)
                    {
                        packetOrder = 0x00;
                    }
                    else
                    {
                        packetOrder = (byte)(i - 1);
                    }
                    response = ReadBinary((byte)(i * PacketSize), PacketSize, packetOrder);
                    Array.Copy(response, 0, CertificateRawHeader, i * PacketSize, response.Length);
                }

                response = ReadBinary((byte)(packetCount * PacketSize), lastPacketSize, (byte)(packetCount - 1));
                Array.Copy(response, 0, CertificateRawHeader, packetCount * PacketSize, response.Length);

                string sertifikaBaslık = Encoding.ASCII.GetString(CertificateRawHeader);

                System.IO.File.WriteAllBytes("sertifika.cer", CertificateRawHeader);
                 X509Certificate cert = new X509Certificate(CertificateRawHeader);
                string test = (sertifikaBaslık);
            }
        }

        private static byte[] selectMF()
        {
            try
            {
                var ctx = ContextFactory.Instance.Establish(SCardScope.System);
                var firstReader = ctx.GetReaders().FirstOrDefault();


                var isoReader = new IsoReader(
                context: ctx,
                readerName: firstReader,
                mode: SCardShareMode.Shared,
                protocol: SCardProtocol.Any,
                releaseContextOnDispose: false);

                string data = "3F00";
                var apdu = new CommandApdu(IsoCase.Case4Short, isoReader.ActiveProtocol)
                {
                    CLA = 0x00, // Class
                    Instruction = (InstructionCode)0xA4,
                    P1 = 0x00,// Parameter 1
                    P2 = 0x00, // Parameter 2
                    Data = StringToByteArray(data),
                    Le = 0x00 // Expected length of the returned data

                };


                //writeLog(">> " + BitConverter.ToString(apdu.ToArray()));

                var response = isoReader.Transmit(apdu);

                if (!response.HasData)
                {
                    //labelStatus.Text = "Error on APDU Command" + " " + "0x" + response.StatusWord.ToString("X");

                    //writeLog("<< Error on APDU Command" + " " + "0x" + response.StatusWord.ToString("X"));

                    return null;

                }
                else
                {

                    string responseData = BitConverter.ToString(response.GetData());

                    responseData = responseData.Replace("-", "");
                    //labelStatus.Text = responseData;

                    //writeLog("<< " + responseData);

                    return response.GetData();

                }

            }
            catch (Exception ex)
            {

                //labelStatus.Text = ex.ToString();
                return null;

            }
        }

        public static byte[] ReadBinary(byte start_index, int size, byte packetOrder)
        {
            try
            {
                var ctx = ContextFactory.Instance.Establish(SCardScope.System);
                var firstReader = ctx.GetReaders().FirstOrDefault();


                var isoReader = new IsoReader(
                context: ctx,
                readerName: firstReader,
                mode: SCardShareMode.Shared,
                protocol: SCardProtocol.Any,
                releaseContextOnDispose: false);

                byte P1_Parameter = 0x00;

                var apdu = new CommandApdu(IsoCase.Case2Short, isoReader.ActiveProtocol)
                {
                    CLA = 0x00, // Class
                    Instruction = (InstructionCode)0xB0,

                    P1 = packetOrder,// Parameter 1
                    P2 = start_index, // Parameter 2
                    Le = size // Expected length of the returned data

                };


              //  writeLog(">> " + BitConverter.ToString(apdu.ToArray()));

                var response = isoReader.Transmit(apdu);

                if (!response.HasData)
                {
                    //labelStatus.Text = "Error on APDU Command" + " " + "0x" + response.StatusWord.ToString("X");

                    //writeLog("<< Error on APDU Command" + " " + "0x" + response.StatusWord.ToString("X"));

                    return null;

                }
                else
                {

                    //labelStatus.Text = BitConverter.ToString(response.GetData());

                    //writeLog("<< " + BitConverter.ToString(response.GetData()));

                    return response.GetData();
                }

            }
            catch (Exception ex)
            {

               // labelStatus.Text = ex.ToString();
                return null;

            }

            // Build a GET CHALLENGE command 

        }

        public static string[] getNameSurname() {
            byte[] fileID = { 0x3D, 0x10, 0x3D, 0x20, 0x2F, 0x11 };
            selectFile(fileID);
            byte[] byteReadData = ReadBinary();
            string[] NameSurname = new string[2];

            //return Encoding.UTF8.GetString(byteReadData, 0, byteReadData.Length).Substring(4, 11);

            byte nameLabel = byteReadData[2];

            if (nameLabel == 0x80) {
                int nameLength = byteReadData[3];
                NameSurname[0] = Encoding.UTF8.GetString(byteReadData, 4, nameLength);

                byte surnameLabel = byteReadData[nameLength + 4];
                if (surnameLabel == 0x81) {
                    int surname_length = byteReadData[nameLength + 5];
                    NameSurname[1] = Encoding.UTF8.GetString(byteReadData, nameLength + 6, surname_length);
                }
            }
            return NameSurname;
        }

        public static byte[] selectFile(string fileID)     
        {
            try
            {
                var ctx = ContextFactory.Instance.Establish(SCardScope.System);
                var firstReader = ctx.GetReaders().FirstOrDefault();


                var isoReader = new IsoReader(
                context: ctx,
                readerName: firstReader,
                mode: SCardShareMode.Shared,
                protocol: SCardProtocol.Any,
                releaseContextOnDispose: false);

                var apdu = new CommandApdu(IsoCase.Case4Short, isoReader.ActiveProtocol)
                {
                    CLA = 0x00, // Class
                    Instruction = (InstructionCode)0xA4,
                    P1 = 0x02,// Parameter 1
                    P2 = 0x00, // Parameter 2
                    Data = StringToByteArray(fileID),
                    Le = 0x00 // Expected length of the returned data

                };


              var log= BitConverter.ToString(apdu.ToArray());

                var response = isoReader.Transmit(apdu);

                if (!response.HasData)
                {
                    //labelStatus.Text = "Error on APDU Command" + " " + "0x" + response.StatusWord.ToString("X");

                    //writeLog("<< Error on APDU Command" + " " + "0x" + response.StatusWord.ToString("X"));
                    return null;
                }
                else
                {
                    string responseData = BitConverter.ToString(response.GetData());

                    responseData = responseData.Replace("-", "");
                    //labelStatus.Text = responseData;

                    //writeLog("<< " + responseData);

                    return response.GetData();
                }


                return null;
            }
            catch (Exception ex) { //labelStatus.Text = ex.ToString(); return null;
                return null;   }

            // Build a GET CHALLENGE command 
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

        static byte[] selectFile(byte[] fileID) {
            try {
                var ctx = ContextFactory.Instance.Establish(SCardScope.System);
                var firstReader = ctx.GetReaders().FirstOrDefault();


                var isoReader = new IsoReader(
                context: ctx,
                readerName: firstReader,
                mode: SCardShareMode.Shared,
                protocol: SCardProtocol.Any,
                releaseContextOnDispose: false);

                //byte[] dataBuffer = { 0x3F, 0x00 };


                var apdu = new CommandApdu(IsoCase.Case4Short, isoReader.ActiveProtocol) {
                    CLA = 0x00, // Class
                    Instruction = (InstructionCode)0xA4,
                    P1 = 0x08,// Parameter 1
                    P2 = 0x00, // Parameter 2
                    Data = fileID,
                    Le = 0x00 // Expected length of the returned data

                };


                var response = isoReader.Transmit(apdu);

                if (!response.HasData) {
                    string error = "Error on APDU Command" + " " + "0x" + response.StatusWord.ToString("X");

                    return null;
                } else {
                    string error = BitConverter.ToString(response.GetData());


                    return response.GetData();
                }

            } catch (Exception ex) {
                return null;
            }

            // Build a GET CHALLENGE command 
        }

        public static byte[] selectDF(string DF)
        {
            try
            {
                var ctx = ContextFactory.Instance.Establish(SCardScope.System);
                var firstReader = ctx.GetReaders().FirstOrDefault();


                var isoReader = new IsoReader(
                context: ctx,
                readerName: firstReader,
                mode: SCardShareMode.Shared,
                protocol: SCardProtocol.Any,
                releaseContextOnDispose: false);

                var apdu = new CommandApdu(IsoCase.Case4Short, isoReader.ActiveProtocol)
                {
                    CLA = 0x00, // Class
                    Instruction = (InstructionCode)0xA4,
                    P1 = 0x01,// Parameter 1
                    P2 = 0x00, // Parameter 2
                    Data = StringToByteArray(DF),
                    Le = 0x00 // Expected length of the returned data

                };


               string log= BitConverter.ToString(apdu.ToArray());

                var response = isoReader.Transmit(apdu);

                if (!response.HasData)
                {
                    //labelStatus.Text = "Error on APDU Command" + " " + "0x" + response.StatusWord.ToString("X");

                    //writeLog("<< Error on APDU Command" + " " + "0x" + response.StatusWord.ToString("X"));

                    return null;

                }
                else
                {

                    string responseData = BitConverter.ToString(response.GetData());

                    responseData = responseData.Replace("-", "");
                    //labelStatus.Text = responseData;

                    //writeLog("<< " + responseData);

                    return response.GetData();

                }

            }
            catch (Exception ex)
            {

                //labelStatus.Text = ex.ToString();
                return null;

            }

        }






    }
}
