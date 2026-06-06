import java.io.*;
import java.net.*;
import java.net.http.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class Honeypot {

    // ========== CORES ==========
    static final String RESET   = "\u001B[0m";
    static final String VERM    = "\u001B[31m";
    static final String VERDE   = "\u001B[32m";
    static final String AMAR    = "\u001B[33m";
    static final String CIANO   = "\u001B[36m";
    static final String NEG     = "\u001B[1m";

    static final String LOG_TXT  = "honeypot_log.txt";
    static final String LOG_HTML = "honeypot_report.html";

    static final int[] PORTAS = { 8080, 2222, 2121, 3307 };

    // Lista de conexões para o relatório HTML
    static final List<String[]> conexoes = Collections.synchronizedList(new ArrayList<>());

    public static void main(String[] args) {
        System.out.println(NEG + CIANO +
            "╔══════════════════════════════════════╗\n" +
            "║     HONEYPOT SHUTDOWN - ATIVO        ║\n" +
            "╚══════════════════════════════════════╝" + RESET);

        for (int porta : PORTAS) {
            final int p = porta;
            new Thread(() -> iniciaServidor(p)).start();
        }

        // Gera relatório HTML a cada 30 segundos
        new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(30000);
                    geraRelatorioHTML();
                } catch (InterruptedException e) { break; }
            }
        }).start();

        try { Thread.currentThread().join(); }
        catch (InterruptedException e) { e.printStackTrace(); }
    }

    static void iniciaServidor(int porta) {
        System.out.println(VERDE + "[+] Escutando porta " + porta +
            " (" + nomeServico(porta) + ")" + RESET);
        try (ServerSocket srv = new ServerSocket(porta)) {
            while (true) {
                Socket cliente = srv.accept();
                new Thread(() -> trataConexao(cliente, porta)).start();
            }
        } catch (IOException e) {
            System.out.println(VERM + "[!] Erro porta " + porta +
                ": " + e.getMessage() + RESET);
        }
    }

    static void trataConexao(Socket cliente, int porta) {
        String ip      = cliente.getInetAddress().getHostAddress();
        String horario = LocalDateTime.now()
            .format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss"));
        String servico = nomeServico(porta);

        try (
            BufferedReader entrada = new BufferedReader(
                new InputStreamReader(cliente.getInputStream()));
            PrintWriter saida = new PrintWriter(cliente.getOutputStream(), true)
        ) {
            saida.println(bannerFalso(porta));

            StringBuilder dados = new StringBuilder();
            long timeout = System.currentTimeMillis() + 2000;
            while (System.currentTimeMillis() < timeout) {
                if (entrada.ready()) {
                    String linha = entrada.readLine();
                    if (linha == null) break;
                    dados.append(linha).append("\n");
                }
            }

            String[] cred = extraiCredenciais(dados.toString());
            String usuario = cred[0], senha = cred[1];

            // Geolocalização do IP (gratuita, sem API key)
            String[] geo = geolocalizaIP(ip);
            String pais   = geo[0];
            String cidade = geo[1];
            String org    = geo[2];

            // Exibe no terminal
            System.out.println(NEG + VERM + "\n⚠  CONEXÃO DETECTADA!" + RESET);
            System.out.println(AMAR + "Serviço : " + RESET + servico + " (" + porta + ")");
            System.out.println(AMAR + "IP      : " + RESET + ip);
            System.out.println(AMAR + "Local   : " + RESET + cidade + " / " + pais);
            System.out.println(AMAR + "Org     : " + RESET + org);
            System.out.println(AMAR + "Horário : " + RESET + horario);
            if (!usuario.isEmpty())
                System.out.println(NEG + VERM + "🔑 LOGIN → " + usuario +
                    " / " + senha + RESET);
            System.out.println(AMAR + "Dados   : " + RESET +
                (dados.length() > 0 ? dados.toString().trim() : "(nenhum)"));
            System.out.println(CIANO + "────────────────────────────────────" + RESET);

            // Salva txt
            salvaLogTXT(ip, horario, servico, porta, usuario, senha,
                pais, cidade, org, dados.toString());

            // Adiciona à lista HTML
            conexoes.add(new String[]{
                horario, ip, pais, cidade, org,
                servico, String.valueOf(porta),
                usuario, senha,
                dados.toString().trim().isEmpty() ? "(nenhum)" : dados.toString().trim()
            });

            geraRelatorioHTML();

        } catch (IOException e) {
            System.out.println(VERM + "[!] Erro com " + ip +
                ": " + e.getMessage() + RESET);
        }
    }

    // ========== GEOLOCALIZAÇÃO GRATUITA ==========
    static String[] geolocalizaIP(String ip) {
        // IPs locais não têm geo
        if (ip.startsWith("127.") || ip.startsWith("192.168") ||
            ip.startsWith("10.") || ip.equals("0:0:0:0:0:0:0:1")) {
            return new String[]{"Local", "Localhost", "Rede local"};
        }
        try {
            HttpClient client = HttpClient.newHttpClient();
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://ip-api.com/json/" + ip +
                    "?fields=country,city,org"))
                .build();
            HttpResponse<String> resp =
                client.send(req, HttpResponse.BodyHandlers.ofString());
            String body = resp.body();

            String pais   = extraiJson(body, "country");
            String cidade = extraiJson(body, "city");
            String org    = extraiJson(body, "org");

            return new String[]{
                pais.isEmpty()   ? "Desconhecido" : pais,
                cidade.isEmpty() ? "Desconhecido" : cidade,
                org.isEmpty()    ? "Desconhecido" : org
            };
        } catch (Exception e) {
            return new String[]{"Erro", "Erro", "Erro"};
        }
    }

    static String extraiJson(String json, String campo) {
        String chave = "\"" + campo + "\":\"";
        int ini = json.indexOf(chave);
        if (ini < 0) return "";
        ini += chave.length();
        int fim = json.indexOf("\"", ini);
        return fim < 0 ? "" : json.substring(ini, fim);
    }

    // ========== RELATÓRIO HTML ==========
    static void geraRelatorioHTML() {
        try (PrintWriter pw = new PrintWriter(new FileWriter(LOG_HTML))) {
            pw.println("""
                <!DOCTYPE html>
                <html lang="pt-br">
                <head>
                <meta charset="UTF-8">
                <title>Honeypot Shutdown - Relatório</title>
                <style>
                  body { background:#0d0d0d; color:#e0e0e0;
                         font-family:monospace; padding:20px; }
                  h1   { color:#00ffcc; border-bottom:1px solid #333; }
                  table { width:100%; border-collapse:collapse; margin-top:20px; }
                  th   { background:#1a1a2e; color:#00ffcc; padding:10px; }
                  td   { padding:8px 10px; border-bottom:1px solid #222; font-size:13px; }
                  tr:hover { background:#1a1a1a; }
                  .ssh   { color:#ff6b6b; }
                  .http  { color:#74b9ff; }
                  .ftp   { color:#fdcb6e; }
                  .mysql { color:#a29bfe; }
                  .cred  { color:#ff4444; font-weight:bold; }
                  .total { color:#00ffcc; font-size:18px; margin:10px 0; }
                </style>
                </head>
                <body>
                <h1>🛡 Honeypot Shutdown — Relatório de Ataques</h1>
                """);

            pw.println("<p class='total'>Total de conexões: <b>" +
                conexoes.size() + "</b></p>");
            pw.println("<p>Atualizado: " + LocalDateTime.now()
                .format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss")) +
                "</p>");

            pw.println("""
                <table>
                <tr>
                  <th>Horário</th><th>IP</th><th>País</th><th>Cidade</th>
                  <th>Org</th><th>Serviço</th><th>Login</th><th>Dados</th>
                </tr>
                """);

            synchronized (conexoes) {
                for (String[] c : conexoes) {
                    String cls = switch (c[5].toLowerCase()) {
                        case "ssh"   -> "ssh";
                        case "ftp"   -> "ftp";
                        case "mysql" -> "mysql";
                        default      -> "http";
                    };
                    String login = c[7].isEmpty() ? "-" :
                        "<span class='cred'>" + c[7] + " / " + c[8] + "</span>";

                    pw.println("<tr>" +
                        "<td>" + c[0] + "</td>" +
                        "<td>" + c[1] + "</td>" +
                        "<td>" + c[2] + "</td>" +
                        "<td>" + c[3] + "</td>" +
                        "<td>" + c[4] + "</td>" +
                        "<td class='" + cls + "'>" + c[5] + ":" + c[6] + "</td>" +
                        "<td>" + login + "</td>" +
                        "<td><small>" + c[9].replace("\n", "<br>") + "</small></td>" +
                        "</tr>");
                }
            }

            pw.println("</table></body></html>");
            System.out.println(VERDE + "[+] Relatório atualizado: " +
                LOG_HTML + RESET);

        } catch (IOException e) {
            System.out.println(VERM + "[!] Erro no HTML: " +
                e.getMessage() + RESET);
        }
    }

    // ========== LOG TXT ==========
    static void salvaLogTXT(String ip, String horario, String servico,
            int porta, String usuario, String senha,
            String pais, String cidade, String org, String dados) {
        try (BufferedWriter bw = new BufferedWriter(
                new FileWriter(LOG_TXT, true))) {
            bw.write("=== CONEXÃO ==="); bw.newLine();
            bw.write("Horário : " + horario); bw.newLine();
            bw.write("Serviço : " + servico + " (" + porta + ")"); bw.newLine();
            bw.write("IP      : " + ip); bw.newLine();
            bw.write("Local   : " + cidade + " / " + pais); bw.newLine();
            bw.write("Org     : " + org); bw.newLine();
            if (!usuario.isEmpty())
                bw.write("LOGIN   : " + usuario + " / " + senha + "\n");
            bw.write("Dados   : " + (dados.isBlank() ? "(nenhum)" : dados.trim()));
            bw.newLine(); bw.newLine();
        } catch (IOException e) {
            System.out.println(VERM + "[!] Erro log txt: " + e.getMessage() + RESET);
        }
    }

    // ========== HELPERS ==========
    static String[] extraiCredenciais(String dados) {
        String usuario = "", senha = "";
        for (String linha : dados.split("\n")) {
            String l = linha.toLowerCase().trim();
            if (l.startsWith("user ") || l.startsWith("login:"))
                usuario = linha.replaceAll("(?i)(user |login:)", "").trim();
            if (l.startsWith("pass ") || l.startsWith("password:"))
                senha = linha.replaceAll("(?i)(pass |password:)", "").trim();
            if (l.startsWith("authorization: basic ")) {
                try {
                    String decoded = new String(Base64.getDecoder()
                        .decode(linha.split(" ")[2]));
                    String[] p = decoded.split(":", 2);
                    if (p.length == 2) { usuario = p[0]; senha = p[1]; }
                } catch (Exception ignored) {}
            }
        }
        return new String[]{usuario, senha};
    }

    static String bannerFalso(int porta) {
        return switch (porta) {
            case 2222 -> "SSH-2.0-OpenSSH_8.9p1 Ubuntu";
            case 2121 -> "220 ProFTPD 1.3.5 Server ready.";
            case 3307 -> "5.7.38-MySQL Community Server";
            default   -> "HTTP/1.1 200 OK\r\n\r\n<h1>Welcome</h1>";
        };
    }

    static String nomeServico(int porta) {
        return switch (porta) {
            case 8080 -> "HTTP";
            case 2222 -> "SSH";
            case 2121 -> "FTP";
            case 3307 -> "MySQL";
            default   -> "Unknown";
        };
    }
}