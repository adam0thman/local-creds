// Reads the SAP Security Audit Log for one user over a lookback window, via
// RSAU_API_GET_LOG_DATA (SAP Note 2926298). Read-only.
//
//   RFC_HOST/RFC_SYSNR/RFC_CLIENT/RFC_USER/RFC_PASSWD  connection (env, never argv)
//   SAL_MINUTES   lookback, default 90
//   SAL_USER      filter to this SLGUSER, default = RFC_USER ("*" for all)
//
// Logon-relevant SAL message ids: AU1 dialog logon OK, AU2 dialog logon FAILED,
// AU5 RFC/CPIC logon OK, AU6 RFC/CPIC logon FAILED, AUM user locked.
import com.sap.conn.jco.*;
import com.sap.conn.jco.ext.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Properties;

public class SalProbe {

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

    /** Field names vary by release, so never assume one exists. */
    static String g(JCoTable t, String f) {
        try {
            String v = t.getString(f);
            return v == null ? "" : v.trim();
        } catch (Exception e) {
            return "";
        }
    }

    public static void main(String[] args) throws Exception {
        Properties p = new Properties();
        p.setProperty(DestinationDataProvider.JCO_ASHOST, env("RFC_HOST", ""));
        p.setProperty(DestinationDataProvider.JCO_SYSNR, env("RFC_SYSNR", "00"));
        p.setProperty(DestinationDataProvider.JCO_CLIENT, env("RFC_CLIENT", ""));
        p.setProperty(DestinationDataProvider.JCO_USER, env("RFC_USER", ""));
        p.setProperty(DestinationDataProvider.JCO_PASSWD, env("RFC_PASSWD", ""));
        p.setProperty(DestinationDataProvider.JCO_LANG, "EN");

        String name = "CREDS_SAL";
        Environment.registerDestinationDataProvider(new MemoryProvider(name, p));

        int minutes = Integer.parseInt(env("SAL_MINUTES", "90"));
        String want = env("SAL_USER", env("RFC_USER", "*"));

        JCoDestination dest = JCoDestinationManager.getDestination(name);
        JCoFunction fn = dest.getRepository().getFunction("RSAU_API_GET_LOG_DATA");
        if (fn == null) {
            System.out.println("RSAU_API_GET_LOG_DATA not available on this system.");
            return;
        }

        LocalDateTime to = LocalDateTime.now(), from = to.minusMinutes(minutes);
        DateTimeFormatter D = DateTimeFormatter.ofPattern("yyyyMMdd");
        DateTimeFormatter T = DateTimeFormatter.ofPattern("HHmmss");
        JCoStructure iv = fn.getImportParameterList().getStructure("IS_INTERVAL");
        iv.setValue("DAT_FROM", from.format(D));
        iv.setValue("TIM_FROM", from.format(T));
        iv.setValue("DAT_TO", to.format(D));
        iv.setValue("TIM_TO", to.format(T));
        fn.execute(dest);

        JCoTable ret = fn.getExportParameterList().getTable("ET_RETURN");
        for (int i = 0; i < ret.getNumRows(); i++) {
            ret.setRow(i);
            String t = ret.getString("TYPE");
            if ("E".equals(t) || "A".equals(t)) {
                System.out.println("API error: " + ret.getString("MESSAGE"));
                return;
            }
        }

        JCoTable log = fn.getExportParameterList().getTable("ET_LOG");
        System.out.printf("SAL rows in window: %d   (last %d min, filter user=%s)%n%n",
                log.getNumRows(), minutes, want);
        System.out.printf("%-6s %-8s %-4s %-6s %-14s %-16s %s%n",
                "TIME", "MSG", "CLI", "USER", "TCODE/REPORT", "TERMINAL", "TEXT");
        System.out.println("-".repeat(120));

        if (log.getNumRows() > 0 && !env("SAL_FIELDS", "").isEmpty()) {
            log.setRow(0);
            StringBuilder sb = new StringBuilder("available columns: ");
            for (int c = 0; c < log.getMetaData().getFieldCount(); c++)
                sb.append(log.getMetaData().getName(c)).append(' ');
            System.out.println(sb + "\n");
        }

        int shown = 0;
        for (int i = 0; i < log.getNumRows(); i++) {
            log.setRow(i);
            String user = g(log, "SLGUSER");
            if (!"*".equals(want) && !want.equalsIgnoreCase(user)) continue;
            String txt = (g(log, "PARAM1") + " " + g(log, "PARAM2") + " "
                        + g(log, "PARAM3") + " " + g(log, "PARAMX")).trim();
            String tc = g(log, "SLGTC");
            if (tc.isEmpty()) tc = g(log, "SLGREPNA");
            String term = g(log, "SLGLTRM2");
            if (term.isEmpty()) term = g(log, "TERM_IPV6");
            System.out.printf("%-6s %-8s %-4s %-6s %-14s %-16s %s%n",
                    g(log, "SAL_TIME"), g(log, "MSG"), g(log, "SLGMAND"), user, tc, term,
                    txt.length() > 60 ? txt.substring(0, 60) : txt);
            shown++;
        }
        if (shown == 0) System.out.println("(no rows matched the user filter)");
        System.exit(0);
    }
}
