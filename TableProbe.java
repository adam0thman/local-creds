// Minimal RFC_READ_TABLE reader. Read-only.
//   RFC_HOST/RFC_SYSNR/RFC_CLIENT/RFC_USER/RFC_PASSWD  connection (env, never argv)
//   TBL     table name
//   COLS    comma-separated field list -- keep this narrow on purpose; never
//           request password-hash columns (BCODE, PASSCODE, PWDSALTEDHASH).
//   WHERE   optional WHERE clause
import com.sap.conn.jco.*;
import com.sap.conn.jco.ext.*;
import java.util.Properties;

public class TableProbe {

    static final class MemoryProvider implements DestinationDataProvider {
        private final String name; private final Properties props;
        MemoryProvider(String n, Properties p) { name = n; props = p; }
        public Properties getDestinationProperties(String n) { return name.equals(n) ? props : null; }
        public void setDestinationDataEventListener(DestinationDataEventListener l) { }
        public boolean supportsEvents() { return false; }
    }

    static String env(String k, String d) {
        String v = System.getenv(k);
        return (v == null || v.isEmpty()) ? d : v;
    }

    static final String[] FORBIDDEN = {"BCODE", "PASSCODE", "PWDSALTEDHASH", "PWDHISTORY"};

    public static void main(String[] a) throws Exception {
        String cols = env("COLS", "");
        for (String bad : FORBIDDEN) {
            if (cols.toUpperCase().contains(bad)) {
                System.out.println("refusing to read column " + bad + " (password hash)");
                return;
            }
        }
        Properties p = new Properties();
        p.setProperty(DestinationDataProvider.JCO_ASHOST, env("RFC_HOST", ""));
        p.setProperty(DestinationDataProvider.JCO_SYSNR, env("RFC_SYSNR", "00"));
        p.setProperty(DestinationDataProvider.JCO_CLIENT, env("RFC_CLIENT", ""));
        p.setProperty(DestinationDataProvider.JCO_USER, env("RFC_USER", ""));
        p.setProperty(DestinationDataProvider.JCO_PASSWD, env("RFC_PASSWD", ""));
        p.setProperty(DestinationDataProvider.JCO_LANG, "EN");
        Environment.registerDestinationDataProvider(new MemoryProvider("CREDS_TAB", p));

        JCoDestination d = JCoDestinationManager.getDestination("CREDS_TAB");
        JCoFunction fn = d.getRepository().getFunction("RFC_READ_TABLE");
        fn.getImportParameterList().setValue("QUERY_TABLE", env("TBL", ""));
        fn.getImportParameterList().setValue("DELIMITER", "|");
        JCoTable f = fn.getTableParameterList().getTable("FIELDS");
        for (String c : cols.split(",")) {
            if (c.trim().isEmpty()) continue;
            f.appendRow(); f.setValue("FIELDNAME", c.trim());
        }
        String where = env("WHERE", "");
        if (!where.isEmpty()) {
            JCoTable o = fn.getTableParameterList().getTable("OPTIONS");
            o.appendRow(); o.setValue("TEXT", where);
        }
        try {
            fn.execute(d);
        } catch (JCoException e) {
            System.out.println("call failed: " + e.getKey() + " " + e.getMessage());
            return;
        }
        JCoTable data = fn.getTableParameterList().getTable("DATA");
        System.out.println(cols);
        System.out.println("-".repeat(40));
        for (int i = 0; i < data.getNumRows(); i++) {
            data.setRow(i);
            System.out.println(data.getString("WA"));
        }
        if (data.getNumRows() == 0) System.out.println("(no rows)");
        System.exit(0);
    }
}
