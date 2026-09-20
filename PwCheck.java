// SAP user / password validity check over RFC.
//
// Answers: is this user usable, and when does its password expire?
//   - USR02 account state: lock flag, failed logons, validity window, last logon
//   - last password change date (field name varies by release, so it is discovered
//     at runtime via DDIF_FIELDINFO_GET rather than hard-coded)
//   - login/password_expiration_time, to turn "changed on X" into "expires in N days"
//   - the user's SECURITY_POLICY, which overrides the profile parameter when set
//
// Reads ONLY account-state columns. Password hash columns are refused outright --
// see FORBIDDEN. Connection parameters arrive via the environment, never argv.
import com.sap.conn.jco.*;
import com.sap.conn.jco.ext.*;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.*;

public class PwCheck {

    static final class MemoryProvider implements DestinationDataProvider {
        private final String name; private final Properties props;
        MemoryProvider(String n, Properties p) { name = n; props = p; }
        public Properties getDestinationProperties(String n) { return name.equals(n) ? props : null; }
        public void setDestinationDataEventListener(DestinationDataEventListener l) { }
        public boolean supportsEvents() { return false; }
    }

    /** Never read these, whatever the release calls them. */
    static final List<String> FORBIDDEN =
        List.of("BCODE", "PASSCODE", "PWDSALTEDHASH", "PWDHISTORY", "OCOD1", "OCOD2");

    /** Candidate names for "date the password was last changed", newest first. */
    static final List<String> PWD_CHANGE_CANDIDATES =
        List.of("PWDCHGDATE", "PASSCHGDATE", "PWDSETDATE", "PWDLGNDATE");

    /** Account-state columns we want when the release has them. */
    static final List<String> WANTED =
        List.of("BNAME", "USTYP", "CLASS", "UFLAG", "LOCNT", "GLTGV", "GLTGB",
                "TRDAT", "ERDAT", "CODVN", "SECURITY_POLICY", "PWDSTATE");

    static String env(String k, String d) {
        String v = System.getenv(k);
        return (v == null || v.isEmpty()) ? d : v;
    }

    static LocalDate sapDate(String s) {
        if (s == null) return null;
        s = s.trim();
        if (s.length() != 8 || s.equals("00000000")) return null;
        try { return LocalDate.parse(s, DateTimeFormatter.ofPattern("yyyyMMdd")); }
        catch (Exception e) { return null; }
    }

    static String show(LocalDate d) { return d == null ? "-" : d.toString(); }

    /** TH_GET_PARAMETER and SPFL_PARAMETER_GET_VALUE use different parameter
     *  names; try both so this works regardless of which one the system exposes. */
    static String readParam(JCoDestination d, String name) {
        String[][] shapes = {
            {"TH_GET_PARAMETER", "PARAMETER_NAME", "PARAMETER_VALUE"},
            {"SPFL_PARAMETER_GET_VALUE", "NAME", "VALUE"},
        };
        for (String[] s : shapes) {
            try {
                JCoFunction fn = d.getRepository().getFunction(s[0]);
                if (fn == null) continue;
                fn.getImportParameterList().setValue(s[1], name);
                fn.execute(d);
                String v = fn.getExportParameterList().getString(s[2]);
                if (v != null && !v.trim().isEmpty()) return v.trim();
            } catch (Exception ignore) {
                // try the next shape
            }
        }
        return null;
    }

    public static void main(String[] a) throws Exception {
        Properties p = new Properties();
        p.setProperty(DestinationDataProvider.JCO_ASHOST, env("RFC_HOST", ""));
        p.setProperty(DestinationDataProvider.JCO_SYSNR, env("RFC_SYSNR", "00"));
        p.setProperty(DestinationDataProvider.JCO_CLIENT, env("RFC_CLIENT", ""));
        p.setProperty(DestinationDataProvider.JCO_USER, env("RFC_USER", ""));
        p.setProperty(DestinationDataProvider.JCO_PASSWD, env("RFC_PASSWD", ""));
        p.setProperty(DestinationDataProvider.JCO_LANG, "EN");
        if (!env("RFC_ROUTER", "").isEmpty())
            p.setProperty(DestinationDataProvider.JCO_SAPROUTER, env("RFC_ROUTER", ""));
        Environment.registerDestinationDataProvider(new MemoryProvider("CREDS_PWCHK", p));

        String who = env("PWCHK_USER", env("RFC_USER", ""));
        JCoDestination d = JCoDestinationManager.getDestination("CREDS_PWCHK");

        // ---- 1. discover which USR02 columns this release actually has ----
        Set<String> present = new LinkedHashSet<>();
        try {
            JCoFunction fi = d.getRepository().getFunction("DDIF_FIELDINFO_GET");
            fi.getImportParameterList().setValue("TABNAME", "USR02");
            fi.execute(d);
            JCoTable t = fi.getTableParameterList().getTable("DFIES_TAB");
            for (int i = 0; i < t.getNumRows(); i++) { t.setRow(i); present.add(t.getString("FIELDNAME").trim()); }
        } catch (Exception e) {
            System.out.println("could not read USR02 metadata: " + e.getMessage());
        }

        String chgField = PWD_CHANGE_CANDIDATES.stream().filter(present::contains).findFirst().orElse(null);
        List<String> cols = new ArrayList<>();
        for (String c : WANTED) if (present.isEmpty() || present.contains(c)) cols.add(c);
        if (chgField != null) cols.add(chgField);
        cols.removeIf(c -> FORBIDDEN.contains(c.toUpperCase()));

        // ---- 2. read the account row ----
        Map<String, String> row = new LinkedHashMap<>();
        try {
            JCoFunction rt = d.getRepository().getFunction("RFC_READ_TABLE");
            rt.getImportParameterList().setValue("QUERY_TABLE", "USR02");
            rt.getImportParameterList().setValue("DELIMITER", "|");
            JCoTable f = rt.getTableParameterList().getTable("FIELDS");
            for (String c : cols) { f.appendRow(); f.setValue("FIELDNAME", c); }
            JCoTable o = rt.getTableParameterList().getTable("OPTIONS");
            o.appendRow(); o.setValue("TEXT", "BNAME = '" + who + "'");
            rt.execute(d);
            JCoTable data = rt.getTableParameterList().getTable("DATA");
            if (data.getNumRows() == 0) { System.out.println("no USR02 row for " + who); return; }
            data.setRow(0);
            String[] parts = data.getString("WA").split("\\|", -1);
            for (int i = 0; i < cols.size() && i < parts.length; i++) row.put(cols.get(i), parts[i].trim());
        } catch (JCoException e) {
            System.out.println("cannot read USR02: " + e.getKey() + " " + e.getMessage()
                + "\n(needs S_TABU_DIS/S_TABU_NAM for table group SC or USR02)");
            return;
        }

        // ---- 3. password policy from profile parameters ----
        // Signatures differ between the two FMs, so try each with its own names
        // rather than assuming one shape. Verified against kernel 754/777.
        Map<String, String> params = new LinkedHashMap<>();
        for (String name : List.of("login/password_expiration_time",
                                   "login/password_max_idle_productive",
                                   "login/password_max_idle_initial",
                                   "login/min_password_lng",
                                   "login/fails_to_user_lock",
                                   "login/password_downwards_compatibility")) {
            params.put(name, readParam(d, name));
        }
        String expDays = params.get("login/password_expiration_time");
        String secPolicy = row.getOrDefault("SECURITY_POLICY", "");

        // ---- 4. report ----
        LocalDate today = LocalDate.now();
        LocalDate changed = sapDate(row.get(chgField));
        LocalDate validTo = sapDate(row.get("GLTGB"));
        LocalDate validFrom = sapDate(row.get("GLTGV"));

        System.out.println("user            : " + row.getOrDefault("BNAME", who)
                           + "   client " + env("RFC_CLIENT", ""));
        System.out.println("type / class    : " + row.getOrDefault("USTYP", "?")
                           + " / " + row.getOrDefault("CLASS", "-"));
        String uflag = row.getOrDefault("UFLAG", "0");
        System.out.println("lock flag       : " + uflag
                           + ("0".equals(uflag) ? "  (not locked)" : "  *** LOCKED ***"));
        System.out.println("failed logons   : " + row.getOrDefault("LOCNT", "?"));
        System.out.println("valid from/to   : " + show(validFrom) + " .. "
                           + (validTo == null ? "no end date" : validTo.toString()
                              + (validTo.isBefore(today) ? "  *** EXPIRED ***" : "")));
        System.out.println("last logon      : " + show(sapDate(row.get("TRDAT"))));
        System.out.println("hash version    : " + row.getOrDefault("CODVN", "?"));
        if (!secPolicy.isEmpty())
            System.out.println("security policy : " + secPolicy
                               + "   (overrides the profile parameter below)");

        boolean future = changed != null && changed.isAfter(today);
        System.out.println("pwd changed on  : " + (chgField == null
            ? "- (no change-date column on this release)"
            : show(changed) + "  [" + chgField + "]"
              + (future ? "  <-- dated in the FUTURE: a sentinel, not a real change date"
                        : "")));

        System.out.println("\npolicy parameters");
        for (Map.Entry<String, String> en : params.entrySet())
            System.out.printf("  %-42s %s%n", en.getKey(),
                              en.getValue() == null ? "(unavailable)" : en.getValue());

        System.out.println();
        if (changed == null) {
            System.out.println("verdict         : no change date available - cannot judge expiry");
        } else if (future) {
            // Seen in the wild: PWDCHGDATE set far ahead so the password never
            // prompts for change. Reporting a negative "age" here would be nonsense.
            System.out.println("verdict         : change date is " + changed
                + ", i.e. in the future. SAP will not force a change; treat the"
                + " password as non-expiring and rotate on your own schedule.");
        } else {
            long age = ChronoUnit.DAYS.between(changed, today);
            System.out.println("password age    : " + age + " day(s)");
            int limit = -1;
            try { limit = Integer.parseInt(expDays.trim()); } catch (Exception ignore) { }
            if (limit > 0) {
                long left = limit - age;
                System.out.println("expires in      : " + left + " day(s)"
                    + (left < 0 ? "  *** ALREADY EXPIRED ***"
                                : left <= 14 ? "  *** ROTATE SOON ***" : ""));
            } else if (limit == 0) {
                System.out.println("expires in      : never (login/password_expiration_time = 0)");
            } else {
                System.out.println("expires in      : unknown (expiration parameter unavailable)");
            }
        }
        if (!secPolicy.isEmpty())
            System.out.println("NOTE            : security policy '" + secPolicy
                + "' is assigned and OVERRIDES the profile parameters above.");
        System.exit(0);
    }
}
