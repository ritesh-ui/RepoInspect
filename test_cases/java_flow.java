import java.io.IOException;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * Enterprise Java Security Test Case
 * Focus: Command Injection and SQL Injection via tainted data flow
 */
public class SecurityVulnerabilities {

    /**
     * Vulnerable Command Injection
     * Flow: userInput -> command -> ProcessBuilder.start()
     */
    public void runCommand(String userInput) throws IOException {
        String command = "ls -la " + userInput;
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);
        pb.start();
    }

    /**
     * Vulnerable SQL Injection
     * Flow: id -> query -> statement.executeQuery()
     */
    public void getUserData(Connection conn, String id) throws Exception {
        String query = "SELECT * FROM users WHERE id = '" + id + "'";
        Statement statement = conn.createStatement();
        ResultSet rs = statement.executeQuery(query);
    }

    /**
     * Safe Usage (AST should ignore this)
     */
    public void safeCall() throws IOException {
        String safeCmd = "date";
        ProcessBuilder pb = new ProcessBuilder(safeCmd);
        pb.start();
    }
}
