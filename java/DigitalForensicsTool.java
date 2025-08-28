import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Scanner;

public class DigitalForensicsTool {
    private final Scanner sc = new Scanner(System.in);
    private final String reportsDir = "forensic_reports";
    private final String recoveredDir = "recovered_files";
    private final List<String> log = new ArrayList<>();

    public static void main(String[] args) {
        DigitalForensicsTool app = new DigitalForensicsTool();
        app.ensureBaseDirs();
        app.menu();
    }

    private void ensureBaseDirs() {
        File r1 = new File(reportsDir);
        if (!r1.exists()) {
            r1.mkdirs();
        }
        File r2 = new File(recoveredDir);
        if (!r2.exists()) {
            r2.mkdirs();
        }
    }

    private void menu() {
        int choice = -1;
        while (choice != 8) {
            System.out.println("\n===== DIGITAL FORENSICS & DATA RECOVERY TOOL =====");
            System.out.println("1. Scan Directory (list files)");
            System.out.println("2. View File Metadata");
            System.out.println("3. Generate File Hash (MD5 / SHA-256)");
            System.out.println("4. Recover Files (copy from a folder)");
            System.out.println("5. Search Keyword Inside Files");
            System.out.println("6. Generate Forensic Report from Log");
            System.out.println("7. Clear Current Session Log");
            System.out.println("8. Exit");
            System.out.print("Enter choice: ");
            String raw = sc.nextLine();
            try {
                choice = Integer.parseInt(raw.trim());
            } catch (NumberFormatException e) {
                choice = -1;
            }

            if (choice == 1) {
                scanDirectory();
            } else if (choice == 2) {
                viewMetadata();
            } else if (choice == 3) {
                generateHash();
            } else if (choice == 4) {
                recoverFiles();
            } else if (choice == 5) {
                searchKeywords();
            } else if (choice == 6) {
                generateReport();
            } else if (choice == 7) {
                clearLog();
            } else if (choice == 8) {
                System.out.println("Exiting... Goodbye!");
            } else {
                System.out.println("Invalid choice. Try again.");
            }
        }
    }

    private void scanDirectory() {
        System.out.print("Enter directory path to scan: ");
        String path = sc.nextLine().trim();
        File dir = new File(path);
        if (!dir.exists() || !dir.isDirectory()) {
            System.out.println("Invalid directory path!");
            return;
        }
        System.out.println("\nFiles in: " + dir.getAbsolutePath());
        File[] files = dir.listFiles();
        if (files == null) {
            System.out.println("No files found or access denied.");
            return;
        }
        for (int i = 0; i < files.length; i++) {
            File f = files[i];
            System.out.println((i + 1) + ". " + f.getName());
        }
        log.add("Scanned directory: " + dir.getAbsolutePath() + " (" + files.length + " entries)");
    }

    private void viewMetadata() {
        System.out.print("Enter file path: ");
        String filePath = sc.nextLine().trim();
        File file = new File(filePath);
        if (!file.exists()) {
            System.out.println("File does not exist!");
            return;
        }
        SimpleDateFormat sdf = new SimpleDateFormat("dd-MM-yyyy HH:mm:ss");
        System.out.println("\n=== FILE METADATA ===");
        System.out.println("Name: " + file.getName());
        System.out.println("Path: " + file.getAbsolutePath());
        System.out.println("Size: " + file.length() + " bytes");
        System.out.println("Readable: " + file.canRead());
        System.out.println("Writable: " + file.canWrite());
        System.out.println("Executable: " + file.canExecute());
        System.out.println("Hidden: " + file.isHidden());
        System.out.println("Last Modified: " + sdf.format(file.lastModified()));
        String type = getFileExtension(file.getName());
        System.out.println("Extension: " + (type.isEmpty() ? "(none)" : type));
        log.add("Metadata viewed for: " + file.getAbsolutePath() + ", size=" + file.length());
    }

    private void generateHash() {
        System.out.print("Enter file path: ");
        String filePath = sc.nextLine().trim();
        File file = new File(filePath);
        if (!file.exists() || !file.isFile()) {
            System.out.println("Invalid file path!");
            return;
        }
        System.out.println("Choose algorithm: 1) MD5  2) SHA-256");
        System.out.print("Enter choice: ");
        String algoChoice = sc.nextLine().trim();
        String algorithm = "SHA-256";
        if ("1".equals(algoChoice)) {
            algorithm = "MD5";
        } else if ("2".equals(algoChoice)) {
            algorithm = "SHA-256";
        } else {
            System.out.println("Invalid choice. Defaulting to SHA-256.");
        }
        String hash = computeHash(filePath, algorithm);
        if (hash != null) {
            System.out.println(algorithm + " hash: " + hash);
            log.add("Hash " + algorithm + " computed for: " + file.getAbsolutePath() + " => " + hash);
        } else {
            System.out.println("Failed to compute hash.");
        }
    }

    private String computeHash(String filePath, String algorithm) {
        FileInputStream fis = null;
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            fis = new FileInputStream(filePath);
            byte[] buffer = new byte[4096];
            int bytesRead = 0;
            while (true) {
                bytesRead = fis.read(buffer);
                if (bytesRead == -1) {
                    break;
                }
                digest.update(buffer, 0, bytesRead);
            }
            byte[] hashBytes = digest.digest();
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hashBytes.length; i++) {
                byte b = hashBytes[i];
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return null;
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                }
            }
        }
    }

    private void recoverFiles() {
        System.out.print("Enter source folder (simulate deleted files folder): ");
        String sourceDir = sc.nextLine().trim();
        File src = new File(sourceDir);
        if (!src.exists() || !src.isDirectory()) {
            System.out.println("Invalid source folder!");
            return;
        }
        System.out.print("Enter destination folder (or press Enter for '" + recoveredDir + "'): ");
        String destInput = sc.nextLine().trim();
        String destDir;
        if (destInput.isEmpty()) {
            destDir = recoveredDir;
        } else {
            destDir = destInput;
        }
        File dest = new File(destDir);
        if (!dest.exists()) {
            dest.mkdirs();
        }
        File[] files = src.listFiles();
        if (files == null) {
            System.out.println("No files to recover or access denied.");
            return;
        }
        int recovered = 0;
        for (int i = 0; i < files.length; i++) {
            File f = files[i];
            if (f.isFile()) {
                Path from = Paths.get(f.getAbsolutePath());
                Path to = Paths.get(dest.getAbsolutePath(), f.getName());
                try {
                    Files.copy(from, to, StandardCopyOption.REPLACE_EXISTING);
                    System.out.println("Recovered: " + f.getName());
                    recovered = recovered + 1;
                } catch (IOException e) {
                    System.out.println("Failed: " + f.getName() + " -> " + e.getMessage());
                }
            }
        }
        log.add("Recovered files from " + src.getAbsolutePath() + " to " + dest.getAbsolutePath() + ": " + recovered + " file(s)");
    }

    private void searchKeywords() {
        System.out.print("Enter root directory to search: ");
        String root = sc.nextLine().trim();
        File dir = new File(root);
        if (!dir.exists() || !dir.isDirectory()) {
            System.out.println("Invalid directory!");
            return;
        }
        System.out.print("Enter keyword (case-insensitive): ");
        String keyword = sc.nextLine();
        if (keyword == null) {
            keyword = "";
        }
        keyword = keyword.trim();
        if (keyword.isEmpty()) {
            System.out.println("Keyword cannot be empty!");
            return;
        }
        System.out.print("Limit by extension (e.g., txt,log,json) or press Enter for all: ");
        String ext = sc.nextLine().trim().toLowerCase(Locale.ROOT);
        List<String> hits = new ArrayList<>();
        searchRecursive(dir, keyword.toLowerCase(Locale.ROOT), ext, hits);
        if (hits.size() == 0) {
            System.out.println("No matches found.");
        } else {
            System.out.println("\nMatches:");
            for (int i = 0; i < hits.size(); i++) {
                System.out.println((i + 1) + ". " + hits.get(i));
            }
        }
        log.add("Keyword search: '" + keyword + "' under " + dir.getAbsolutePath() + " -> " + hits.size() + " match(es)");
    }

    private void searchRecursive(File current, String keywordLower, String ext, List<String> hits) {
        File[] list = current.listFiles();
        if (list == null) {
            return;
        }
        for (int i = 0; i < list.length; i++) {
            File f = list[i];
            if (f.isDirectory()) {
                searchRecursive(f, keywordLower, ext, hits);
            } else {
                boolean ok = true;
                if (ext != null && !ext.isEmpty()) {
                    String e = getFileExtension(f.getName()).toLowerCase(Locale.ROOT);
                    if (!e.equals(ext)) {
                        ok = false;
                    }
                }
                long size = f.length();
                if (size > 5L * 1024L * 1024L) {
                    ok = false;
                }
                if (ok) {
                    boolean found = scanFileForKeyword(f, keywordLower);
                    if (found) {
                        hits.add(f.getAbsolutePath());
                    }
                }
            }
        }
    }

    private boolean scanFileForKeyword(File file, String keywordLower) {
        BufferedReader br = null;
        try {
            br = new BufferedReader(new FileReader(file));
            String line;
            int lineNo = 0;
            while (true) {
                line = br.readLine();
                if (line == null) {
                    break;
                }
                lineNo = lineNo + 1;
                String check = line.toLowerCase(Locale.ROOT);
                if (check.contains(keywordLower)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            return false;
        } finally {
            if (br != null) {
                try {
                    br.close();
                } catch (IOException e) {
                }
            }
        }
    }

    private void generateReport() {
        if (log.size() == 0) {
            System.out.println("No log entries in this session. Perform some actions first.");
            return;
        }
        String name = "report_" + System.currentTimeMillis() + ".txt";
        Path path = Paths.get(reportsDir, name);
        FileWriter fw = null;
        try {
            fw = new FileWriter(path.toFile());
            fw.write("===== FORENSIC REPORT =====\n");
            fw.write("Generated on: " + LocalDateTime.now() + "\n\n");
            for (int i = 0; i < log.size(); i++) {
                fw.write((i + 1) + ") " + log.get(i) + "\n");
            }
            fw.flush();
            System.out.println("Report saved at: " + path.toAbsolutePath());
        } catch (IOException e) {
            System.out.println("Error generating report: " + e.getMessage());
        } finally {
            if (fw != null) {
                try {
                    fw.close();
                } catch (IOException e) {
                }
            }
        }
    }

    private void clearLog() {
        log.clear();
        System.out.println("Session log cleared.");
    }

    private String getFileExtension(String name) {
        int idx = name.lastIndexOf('.') ;
        if (idx == -1) {
            return "";
        }
        if (idx == name.length() - 1) {
            return "";
        }
        return name.substring(idx + 1);
    }
}
