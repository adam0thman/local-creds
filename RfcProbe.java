// Real SAP RFC logon probe for `creds`. Run as a single-file source program:
//   java --enable-native-access=ALL-UNNAMED -cp <lib>/sapjco3.jar \
//        -Djava.library.path=<lib> RfcProbe.java
//
// Every parameter arrives via the environment, never argv -- argv is world-readable
// through `ps`, and one of these parameters is a production password.
//
// Emits a single JSON object on stdout. Nothing else is printed.
import com.sap.conn.jco.*;
import com.sap.conn.jco.ext.*;
import java.util.Properties;

public class RfcProbe {

    /** Feeds JCo its destination from memory, so the password never reaches disk. */
    static final class MemoryProvider implements DestinationDataProvider {
        private final String name;
        private final Properties props;
        MemoryProvider(String name, Properties props) { this.name = name; this.props = props; }
        public Properties getDestinationProperties(String n) { return name.equals(n) ? props : null; }
        public void setDestinationDataEventListener(DestinationDataEventListener l) { }
        public boolean supportsEvents() { return false; }
    }

    static String env(String k, String dflt) {
        String v = System.getenv(k);
        return (v == null || v.isEmpty()) ? dflt : v;
    }

    static String esc(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\").replace("\"", "\\\"")
                .replace("\n", " ").replace("\r", " ").replace("\t", " ");
    }

    public static void main(String[] args) {
        Properties p = new Properties();
        String mshost = env("RFC_MSHOST", "");
        String group  = env("RFC_GROUP", "");

        if (!mshost.isEmpty()) {                       // load-balanced (type B)
            p.setProperty(DestinationDataProvider.JCO_MSHOST, mshost);
            if (!env("RFC_MSSERV", "").isEmpty())
                p.setProperty(DestinationDataProvider.JCO_MSSERV, env("RFC_MSSERV", ""));
            if (!env("RFC_R3NAME", "").isEmpty())
                p.setProperty(DestinationDataProvider.JCO_R3NAME, env("RFC_R3NAME", ""));
            if (!group.isEmpty())
                p.setProperty(DestinationDataProvider.JCO_GROUP, group);
        } else {                                       // specific app server (type A)
            p.setProperty(DestinationDataProvider.JCO_ASHOST, env("RFC_HOST", ""));
            p.setProperty(DestinationDataProvider.JCO_SYSNR,  env("RFC_SYSNR", "00"));
        }
        p.setProperty(DestinationDataProvider.JCO_CLIENT, env("RFC_CLIENT", ""));
        p.setProperty(DestinationDataProvider.JCO_USER,   env("RFC_USER", ""));
        p.setProperty(DestinationDataProvider.JCO_PASSWD, env("RFC_PASSWD", ""));
        p.setProperty(DestinationDataProvider.JCO_LANG,   env("RFC_LANG", "EN"));
        if (!env("RFC_ROUTER", "").isEmpty())
            p.setProperty(DestinationDataProvider.JCO_SAPROUTER, env("RFC_ROUTER", ""));
        // Override for a gateway that is not on the standard sapgw<NN> (33<NN>) port --
        // JCo otherwise derives that port purely from SYSNR with no way to override it.
        if (!env("RFC_GWSERV", "").isEmpty())
            p.setProperty(DestinationDataProvider.JCO_GWSERV, env("RFC_GWSERV", ""));
        if (!env("RFC_GWHOST", "").isEmpty())
            p.setProperty(DestinationDataProvider.JCO_GWHOST, env("RFC_GWHOST", ""));

        String name = "CREDS_PROBE";
        try {
            Environment.registerDestinationDataProvider(new MemoryProvider(name, p));
        } catch (IllegalStateException alreadyRegistered) {
            // one probe per JVM; nothing to do
        }

        long t0 = System.currentTimeMillis();
        try {
            JCoDestination d = JCoDestinationManager.getDestination(name);
            d.ping();
            long ms = System.currentTimeMillis() - t0;
            JCoAttributes a = d.getAttributes();
            System.out.printf(
                "{\"ok\":true,\"ms\":%d,\"detail\":\"RFC logon SUCCEEDED as %s on %s client %s"
                + " (%s, kernel %s)\"}%n",
                ms, esc(a.getUser()), esc(a.getSystemID()), esc(a.getClient()),
                esc(a.getPartnerHost()), esc(a.getKernelRelease()));
        } catch (JCoException e) {
            // group/key are the actionable part: LOGON_FAILURE vs COMMUNICATION_FAILURE
            // is the difference between a wrong password and an unreachable host.
            System.out.printf("{\"ok\":false,\"group\":%d,\"key\":\"%s\",\"detail\":\"%s\"}%n",
                e.getGroup(), esc(e.getKey()), esc(e.getMessage()));
        } catch (Throwable t) {
            System.out.printf("{\"ok\":false,\"key\":\"%s\",\"detail\":\"%s\"}%n",
                esc(t.getClass().getSimpleName()), esc(String.valueOf(t.getMessage())));
        }
        System.exit(0);
    }
}
