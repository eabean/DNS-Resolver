package ca.ubc.cs317.dnslookup;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashSet;


public class DNSQueryHandler {

    private static final int DEFAULT_DNS_PORT = 53;
    private static DatagramSocket socket;
    private static boolean verboseTracing = false;

    private static final Random random = new Random();
    private static ByteBuffer globalResponseBuffer;

    /**
     * Sets up the socket and set the timeout to 5 seconds
     *
     * @throws SocketException if the socket could not be opened, or if there was an
     *                         error with the underlying protocol
     */
    public static void openSocket() throws SocketException {
        socket = new DatagramSocket();
        socket.setSoTimeout(5000);
    }

    /**
     * Closes the socket
     */
    public static void closeSocket() {
        socket.close();
    }

    /**
     * Set verboseTracing to tracing
     */
    public static void setVerboseTracing(boolean tracing) {
        verboseTracing = tracing;
    }

    // given a byte array, removes any trailing zeroes from it
    public static byte[] removeTrailingZeroes(byte[] questionPacket){

        int packetLength = questionPacket.length - 1;

        while(questionPacket[packetLength] == 0)
        {
            --packetLength;
        }

        return Arrays.copyOf(questionPacket, packetLength+1);

    }

    // converts 2 bytes into its decimal value
    private static int decodeTwoOctets(byte b1, byte b2) {
        return (((int) b1 & 0xFF) << 8) + ((int) b2 & 0xFF);
    }

    // converts 4 bytes into a decimal value
    private static int decodeTTL(byte b1, byte b2, byte b3, byte b4) {
        return (((int) b1 & 0xFF) << 24) + (((int) b2 & 0xFF) << 16) +
                (((int) b3 & 0xFF) << 8) + (((int) b4 & 0xFF));
    }


    /**
     * Builds the query, sends it to the server, and returns the response.
     *
     * @param message Byte array used to store the query to DNS servers.
     * @param server  The IP address of the server to which the query is being sent.
     * @param node    Host and record type to be used for search.
     * @return A DNSServerResponse Object containing the response buffer and the
     *         transaction ID.
     * @throws IOException if an IO Exception occurs
     */
    public static DNSServerResponse buildAndSendQuery(byte[] message, InetAddress server, DNSNode node)
            throws IOException {

        // encode header section
        ByteBuffer header = ByteBuffer.allocate(12);

        // set up queryID and get string and int forms of it
        int rnd = random.nextInt(65535);
        byte[] queryID = new byte[] { (byte) ((rnd >> 8) & 0x7F), (byte) (rnd & 0x7F)};
        int qID = decodeTwoOctets(queryID[0], queryID[1]);
        String qIDString = Integer.toString(qID);


        byte[] flags = new byte[] { (byte) 0x01, (byte) 0x00 };
        byte[] qdCount = new byte[] { (byte) 0x00, (byte) 0x01 };
        byte[] anCount = new byte[] { (byte) 0x00, (byte) 0x00 };
        byte[] nsCount = new byte[] { (byte) 0x00, (byte) 0x00 };
        byte[] arCount = new byte[] { (byte) 0x00, (byte) 0x00 };
        header.put(queryID);
        header.put(flags);
        header.put(qdCount);
        header.put(anCount);
        header.put(nsCount);
        header.put(arCount);

        // encode question section
        ByteBuffer question = ByteBuffer.allocate(70);

        //encode QNAME
        String domainName = node.getHostName();
        String[] sections = domainName.split("\\.");

        for (int i = 0; i < sections.length; i++) {

            String part = sections[i];

            byte[] lengthAndLabel = new byte[part.length() + 1];
            lengthAndLabel[0] = (byte) part.length();
            byte[] stringBytes = part.getBytes(StandardCharsets.UTF_8);

            for (int j = 1; j < part.length() + 1; j++) {
                lengthAndLabel[j] = stringBytes[j - 1];
            }

            question.put(lengthAndLabel);
        }

        // signal end of QNAME
        question.put((byte) 0x00);

        //encode QTYPE, QCLASS
        int recordType = node.getType().getCode();
        byte[] qType = new byte[] { (byte) 0x00, (byte) recordType };
        byte[] qClass = new byte[] { (byte) 0x00, (byte) 0x01 };
        question.put(qType);
        question.put(qClass);

        // prepping transfer of header and question sections into byte[] message
        byte[] headerSection = header.array();
        byte[] questionSection = question.array();
        questionSection = removeTrailingZeroes(questionSection);

        // copying sections into message
        message = new byte[headerSection.length + questionSection.length];
        System.arraycopy(headerSection,0,message,0,headerSection.length);
        System.arraycopy(questionSection,0,message,headerSection.length,questionSection.length);

        // send the query through the socket
        int messageLength = message.length;
        DatagramPacket dnsPacket = new DatagramPacket(message, messageLength, server, DEFAULT_DNS_PORT);
        socket.send(dnsPacket);

        // prepping response buffer
        byte[] buffer = new byte[1024];
        socket.setSoTimeout(5000);

        while (true) {
            // construct DataPacket to recieve response from DNS
            DatagramPacket response = new DatagramPacket(buffer, buffer.length);

            try {

                // print query we are sending to DNS
                if (verboseTracing) {
                    System.out.println("\n\n");
                    System.out.println("Query ID     " + qIDString + " " + node.getHostName()
                            + "  " + node.getType() + " --> " + server);
                }

                socket.receive(response);

            // if socket times out, send the packet again
            } catch (SocketTimeoutException e) {
                socket.send(dnsPacket);
                continue;
            }

            // get the data from the response and put it into a response and return it
            byte[] socketResponse = response.getData();
            ByteBuffer dnsResponse = ByteBuffer.wrap(socketResponse);
            return new DNSServerResponse(dnsResponse, qID);
        }
    }


    // resolves a FQDN name and returns it as a String, setting position of globalResponse buffer to correct index
    private static String decodeDomainName(ByteBuffer responseBuffer, String domainName) {

        byte partLength = (responseBuffer.get());

        if(partLength == 0) {
            if(domainName.length() > 0){
            domainName = domainName.substring(0, domainName.length()-1);
            }
            return domainName;

        } else if (partLength <= -64 && partLength > -255) {
            int offset = (responseBuffer.get() & 0xFF);
            int returnIndex = responseBuffer.position();
            responseBuffer.position(offset);
            domainName = decodeDomainName(responseBuffer, domainName);
            responseBuffer.position(returnIndex);
            return domainName;

        } else {

            int max = responseBuffer.position() + partLength;

            while(responseBuffer.position() < max) {
                char c = (char) responseBuffer.get();
                domainName += c;

            }
            domainName += '.';
            return decodeDomainName(responseBuffer, domainName);
        }

    }



    /**
     * Decodes the DNS server response and caches it.
     *
     * @param transactionID  Transaction ID of the current communication with the
     *                       DNS server
     * @param responseBuffer DNS server's response
     * @param cache          To store the decoded server's response
     * @return A set of resource records corresponding to the name servers of the
     *         response.
     */
    public static Set<ResourceRecord> decodeAndCacheResponse(int transactionID, ByteBuffer responseBuffer, DNSCache cache) throws UnknownHostException {

        Set<ResourceRecord> resourceRecordSet = new HashSet<>();
        globalResponseBuffer = responseBuffer;

        int queryID = decodeTwoOctets(responseBuffer.get(), responseBuffer.get());

        if (queryID != transactionID) {
            return null;
        }

        byte flagsOne = responseBuffer.get();
        byte flagsTwo = responseBuffer.get();
        int QR = (((int) flagsOne & 0xFF) >> 7);
        int OPCODE = ((flagsOne & 0x78) >> 3);
        int AA = (int) ((flagsOne & 0x04) >> 2);
        int TC = ((flagsOne & 0x02) >> 1);
        int RD = (flagsOne & 0x01);
        int RA = (flagsTwo >> 7);
        int Z = ((flagsTwo & 0x70) >> 4);
        int RCODE = (flagsTwo & 0x0F);

        switch(RCODE){
			      case 1:
            case 2:
            case 3:
            case 4:
            case 5:
                return null;
            default:
                break;
        }

        int QDCOUNT = decodeTwoOctets(responseBuffer.get(), responseBuffer.get());
        int ANCOUNT = decodeTwoOctets(responseBuffer.get(), responseBuffer.get());
        int NSCOUNT = decodeTwoOctets(responseBuffer.get(), responseBuffer.get());
        int ARCOUNT= decodeTwoOctets(responseBuffer.get(), responseBuffer.get());

        if (verboseTracing)
            System.out.println("Response ID: " + queryID + " Authoritative = " + ((AA == 1) ? "true" : "false"));

        // decode FQDN from response
        String FQDN = "";
        FQDN = decodeDomainName(globalResponseBuffer, FQDN);

        int QTYPE = decodeTwoOctets(globalResponseBuffer.get(), globalResponseBuffer.get());
        int QCODE = decodeTwoOctets(globalResponseBuffer.get(), globalResponseBuffer.get());


        if (verboseTracing)
            System.out.println("  Answers (" + ANCOUNT + ")");

        for (int i = 0; i < ANCOUNT; i++) {
            ResourceRecord rr = parseRecord(responseBuffer);
            verbosePrintResourceRecord(rr, rr.getType().getCode());
            cache.addResult(rr);
            resourceRecordSet.add(rr);
        }

        if (verboseTracing)
            System.out.println("  Nameservers (" + NSCOUNT + ")");

        for (int i = 0; i < NSCOUNT; i++) {
            ResourceRecord rr = parseRecord(responseBuffer);
            verbosePrintResourceRecord(rr, rr.getType().getCode());
            cache.addResult(rr);
            resourceRecordSet.add(rr);
        }

        if (verboseTracing)
            System.out.println("  Additional Information (" + ARCOUNT + ")");

        for (int i = 0; i < ARCOUNT; i++) {
            ResourceRecord rr = parseRecord(responseBuffer);
            verbosePrintResourceRecord(rr, rr.getType().getCode());
            cache.addResult(rr);
            resourceRecordSet.add(rr);
        }

        return resourceRecordSet;
    }

    //parses a single ResourceRecord and returns it to decodeAndCacheResponse
    private static ResourceRecord parseRecord(ByteBuffer responseBuffer) {

        // decode resource record name
        String NAME = "";
        NAME = decodeDomainName(responseBuffer, NAME);

        int TYPE = decodeTwoOctets(responseBuffer.get(), responseBuffer.get());
        int CLASS = decodeTwoOctets(responseBuffer.get(), responseBuffer.get());
        long TTL = decodeTTL(responseBuffer.get(), responseBuffer.get(), responseBuffer.get(), responseBuffer.get());
        int RDLENGTH = decodeTwoOctets(responseBuffer.get(), responseBuffer.get());

        String value = "";

        switch (TYPE) {
            case 1: // A
                value = "";
                for (int i = 0; i < RDLENGTH; i++) {
                    int decimalVal = (int) (responseBuffer.get() & 0xFF);
                    value += Integer.toString(decimalVal);
                    value += '.';
                }
                value = value.substring(0, value.length() - 1);
                break;
            case 28: // AAAA
                value = "";
                for (int i = 0; i < RDLENGTH / 2; i++) {
                    int decimalVal = decodeTwoOctets(responseBuffer.get(), responseBuffer.get());
                    value += Integer.toHexString(decimalVal);
                    value += ':';
                }
                value = value.substring(0, value.length() - 1);
                break;
            case 15: // MX
                responseBuffer.position(responseBuffer.position() + 2);
                value = decodeDomainName(responseBuffer, value);
                break;
            case 6: //SOA
                 value = decodeDomainName(responseBuffer, value);
                 break;
            default: // NS, CNAME
                value = decodeDomainName(responseBuffer, value);
        }

        if (TYPE == 1 || TYPE == 28) {
            try {
                InetAddress address = InetAddress.getByName(value);
                return new ResourceRecord(NAME, RecordType.getByCode(TYPE), TTL, address);

            } catch (UnknownHostException e) {
                //System.err.println("UnknownHostException");
            }
        }

        return new ResourceRecord(NAME, RecordType.getByCode(TYPE), TTL, value);

    }

    /**
     * Formats and prints record details (for when trace is on)
     *
     * @param record The record to be printed
     * @param rtype  The type of the record to be printed
     */
    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(), record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(), record.getTextResult());
    }
}
