/*
 * WsDualScanner v0.1 - 2/8/2010
 * Remote port probing utility for WCF web services
 * using the WsDualHttpBinding.  Use at your own risk.
 * 
 * Brian Holyfield
 * Gotham Digital Science
 * labs@gdssecurity.com
 * 
 */

using System;
using System.Net;
using System.Xml;
using System.IO;
using System.Diagnostics;

namespace WsDualScanner
{
    enum Mode
    {
        Sweep = 1,
        Scan = 2
    }

    class Program
    {
        static void Main(string[] args)
        {
            Mode mode;
            int iStart, iStop, iPort;
            string strIP, strServiceUrl, strTested;
            string strReport = String.Empty;
            bool finished = false;
            
            //Check the command line args
            try
            {
                if (args[0].ToString().Equals("-h") )
                {
                    mode = Mode.Scan;
                    strIP = args[1];
                    iStart = int.Parse(args[2]);
                    iStop = int.Parse(args[3]);
                    strServiceUrl = args[4];
                    iPort = 0;
                }
                else if (args[0].ToString().Equals("-s"))
                {
                    mode = Mode.Sweep;
                    strIP = args[1];
                    iStart = int.Parse(args[2]);
                    iStop = int.Parse(args[3]);
                    iPort = int.Parse(args[4]);
                    strServiceUrl = args[5];
                } 
                else 
                {
                    throw new Exception();
                }
            }
            catch
            {
                Console.WriteLine("\nWsDualScanner v0.1 - Port Scanner for WCF Dual Http Service Binding");
                Console.WriteLine("\nBrian Holyfield - Gotham Digital Science (labs@gdssecurity.com)\n");
                Console.WriteLine("Usage:\n");
                Console.WriteLine("   Example 1: WsDualScanner -h X.X.X.X StartPort EndPort ServiceAddress\n");
                Console.WriteLine("   Example 2: WsDualScanner -s X.X.X StartIp EndIp PortNumber ServiceAddress\n");
                return;
            }

            // Start the scanning logic
            Console.WriteLine("Starting...");
            for (int counter = iStart; counter <= iStop+1; counter++)
            {
                if (counter == iStop + 1)
                {
                    // For the last request, we will just re-issue another
                    // request to the last port. The destination here doesn't
                    // matter, it's the response time from the previous request
                    // we are interested in.
                    counter = iStop;
                    finished = true;
                }
                try
                {   
                    System.Diagnostics.Stopwatch timer = new Stopwatch();
                    timer.Start();
                    Prober p = new Prober();
                    if (mode.Equals(Mode.Scan))
                    {
                        // Scanning a single host, so counter is the port
                        strTested = strIP + ":" + counter;
                        p.Probe(strIP, counter, strServiceUrl);
                    }
                    else
                    {
                        // Sweeping a range for a port, so counter is the last IP octet
                        strTested = strIP + "." + counter.ToString() + ":" + iPort;
                        p.Probe(strIP + "." + counter.ToString(), iPort, strServiceUrl);

                    }

                    // Measure the response time
                    timer.Stop();
                    TimeSpan timeTaken = timer.Elapsed;
                    
                    // Report the Results
                    if (iStart != counter)
                    {
                        if (timeTaken.Seconds > 5)
                        {
                            Console.WriteLine("Probe TIMEOUT: " + strReport + "\nResponse Time: " + timeTaken.ToString() + "\n");
                        }
                        else if (timeTaken.TotalMilliseconds < 500)
                        {
                            Console.WriteLine("FAST Probe Response: " + strReport + "\nResponse Time: " + timeTaken.ToString() + "\n");
                        }
                        else
                        {
                            Console.WriteLine("Probe Response: " + strReport + "\nResponse Time: " + timeTaken.ToString() + "\n");
                        }
                    }

                    // We'll need this value on the next loop iteration
                    strReport = strTested;

                    // Ok, we're done
                    if (finished)
                    {
                        Console.WriteLine("Done!");
                        break;
                    }
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception: " + e.Message.ToString());
                }
            }
        }
    }

    public class Prober
    {
        public Prober()
        {
        }

        public void Probe(string host, int port, string strServiceUrl)
        {
            // This method sends the CreateSequence Request used to 
            // do our port probing.
            HttpWebRequest myRequest = (HttpWebRequest)WebRequest.Create(strServiceUrl);
            
            // Our timeout is set to one minute since we don't want to timeout before 
            // the web service does, otherwise we can't measure the server-side timeout
            myRequest.Timeout = 60000;
            myRequest.Method = "POST";
            myRequest.ContentType = "application/soap+xml";
            Console.WriteLine("Testing " + host + ":" + port.ToString() + "\n");
            string strPostData = genSoap(host, port);

            myRequest.ContentLength = strPostData.Length;

            StreamWriter swRequestWriter = new StreamWriter(myRequest.GetRequestStream());
            swRequestWriter.Write(strPostData);
            swRequestWriter.Close();
            HttpWebResponse myResponse = (HttpWebResponse)myRequest.GetResponse();
        }

        public string genSoap(string strHost, int intPort)
        {
            // This method generates the CreateSequence request
            StringWriter sw = new StringWriter();
            XmlTextWriter xmlWriter;
            xmlWriter = new XmlTextWriter(sw);

            xmlWriter.Formatting = Formatting.Indented;
            xmlWriter.Indentation = 4;

            xmlWriter.WriteStartElement("s:Envelope");
            xmlWriter.WriteAttributeString("xmlns:s", "http://www.w3.org/2003/05/soap-envelope");
            xmlWriter.WriteAttributeString("xmlns:a", "http://www.w3.org/2005/08/addressing");
            xmlWriter.WriteStartElement("s:Header");
            xmlWriter.WriteStartElement("a:Action");
            xmlWriter.WriteAttributeString("s:mustUnderstand", "1");
            xmlWriter.WriteString("http://schemas.xmlsoap.org/ws/2005/02/rm/CreateSequence");
            xmlWriter.WriteEndElement();

            xmlWriter.WriteStartElement("a:MessageID");
            xmlWriter.WriteString("urn:uuid:foobar");
            xmlWriter.WriteEndElement();

            xmlWriter.WriteStartElement("a:ReplyTo");
            xmlWriter.WriteStartElement("a:Address");
            xmlWriter.WriteString("http://" + strHost + ":" + intPort.ToString() + "/test");
            xmlWriter.WriteEndElement();
            xmlWriter.WriteEndElement();

            xmlWriter.WriteStartElement("a:To");
            xmlWriter.WriteAttributeString("s:mustUnderstand", "1");
            xmlWriter.WriteString("http://foobar/blah.svc");
            xmlWriter.WriteEndElement();

            xmlWriter.WriteEndElement();

            xmlWriter.WriteStartElement("s:Body");
            xmlWriter.WriteStartElement("CreateSequence");

            xmlWriter.WriteAttributeString("xmlns", "http://schemas.xmlsoap.org/ws/2005/02/rm");
            xmlWriter.WriteEndElement();
            xmlWriter.WriteEndElement();
            xmlWriter.WriteEndElement();
            return sw.ToString();
        }
    }
}
