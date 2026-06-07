import java.io.*;
import java.net.*;
import java.net.http.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

public class Honeypot {

    // ========== CORES TERMINAL ==========
    static final String RESET = "\u001B[0m";
    static final String VERM  = "\u001B[31m";
    static final String VERDE = "\u001B[32m";
    static final String AMAR  = "\u001B[33m";
    static final String CIANO = "\u001B[36m";
    static final String MAG   = "\u001B[35m";
    static final String NEG   = "\u001B[1m";
    static final String DIM   = "\u001B[2m";

    // ========== ARQUIVOS ==========
    static final String LOG_TXT      = "honeypot_log.txt";
    static final String LOG_HTML     = "honeypot_report.html";
    static final String BLOCKED_FILE = "blocked_ips.txt";
    static final long   MAX_LOG_SIZE = 10L * 1024 * 1024;

    // ========== CONFIG ==========
    static final int[] PORTAS    = { 8080, 2222, 2121, 3307, 23, 6379, 9200 };
    static final int   MAX_BODY  = 8192;
    static final int   MAX_HDRS  = 4096;
    static final int   MAX_CONN  = 50;
    static final int   MAX_LOG   = 1000;
    static final int   RATE_LIM  = 15;
    static final long  BRUTE_WIN = 60_000;
    static final int   CONN_TIMEOUT = 3000;
    static final int   MAX_PAYLOAD_LOG = 2048;

    // ========== ESTADO ==========
    static final List<String[]>          conexoes    = Collections.synchronizedList(new ArrayList<>());
    static final Map<String,Integer>     contadorIP  = new ConcurrentHashMap<>();
    static final Set<String>             bloqueados  = ConcurrentHashMap.newKeySet();
    static final Map<String,String[]>    cacheGeo    = new ConcurrentHashMap<>();
    static final Map<String,List<Long>>  bruteForce  = new ConcurrentHashMap<>();
    static final AtomicLong              totalConn   = new AtomicLong(0);
    static final AtomicLong              totalBloq   = new AtomicLong(0);
    static final ExecutorService         pool        = Executors.newFixedThreadPool(MAX_CONN);
    static final Map<String,Long>        ultimaConn  = new ConcurrentHashMap<>();
    static final ScheduledExecutorService scheduler  = Executors.newScheduledThreadPool(4);
    // Proteção: log de payloads suspeitos separado
    static final String LOG_THREATS = "threats.txt";

    public static void main(String[] args) {
        printBanner();
        carregaBloqueados();

        for (int porta : PORTAS) {
            final int p = porta;
            new Thread(() -> iniciaServidor(p), "srv-" + p).start();
        }

        scheduler.scheduleAtFixedRate(Honeypot::geraRelatorioHTML,  10, 30, TimeUnit.SECONDS);
        scheduler.scheduleAtFixedRate(Honeypot::printStats,         60, 60, TimeUnit.SECONDS);
        scheduler.scheduleAtFixedRate(Honeypot::rotacionaLog,        1,  1, TimeUnit.HOURS);
        scheduler.scheduleAtFixedRate(() -> {
            if (cacheGeo.size() > 500) cacheGeo.clear();
        }, 10, 10, TimeUnit.MINUTES);
        scheduler.scheduleAtFixedRate(() -> {
            long now = System.currentTimeMillis();
            bruteForce.forEach((ip, ts) -> {
                ts.removeIf(t -> now - t > BRUTE_WIN * 2);
                if (ts.isEmpty()) bruteForce.remove(ip);
            });
            // Limpa ultimaConn antigos (>5min)
            ultimaConn.entrySet().removeIf(e -> now - e.getValue() > 300_000);
        }, 2, 2, TimeUnit.MINUTES);

        iniciaPainelControle();
        try { Thread.currentThread().join(); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    static void printBanner() {
        System.out.println(NEG + CIANO);
        System.out.println("  ╔══════════════════════════════════════════════╗");
        System.out.println("  ║   ██╗  ██╗ ██████╗ ███╗  ██╗███████╗██╗   ║");
        System.out.println("  ║   ██║  ██║██╔═══██╗████╗ ██║██╔════╝╚██╗  ║");
        System.out.println("  ║   ███████║██║   ██║██╔██╗██║█████╗   ╚██╗ ║");
        System.out.println("  ║   ██╔══██║██║   ██║██║╚████║██╔══╝   ██╔╝ ║");
        System.out.println("  ║   ██║  ██║╚██████╔╝██║ ╚███║███████╗██╔╝  ║");
        System.out.println("  ║   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚══╝╚══════╝╚═╝  ║");
        System.out.println("  ║     HONEYPOT v5.0 — SHUTDOWN SECURITY       ║");
        System.out.println("  ╚══════════════════════════════════════════════╝" + RESET);
        System.out.println();
    }

    static void printStats() {
        long sc = conexoes.stream().filter(c -> "SCANNER".equals(c[10])).count();
        long br = conexoes.stream().filter(c -> "BRUTE".equals(c[10])).count();
        long cr = conexoes.stream().filter(c -> !c[7].isEmpty()).count();
        System.out.println(DIM + CIANO +
            "\n  ┌─ STATS ─────────────────────────────┐" +
            "\n  │  Conexoes  : " + totalConn.get() +
            "\n  │  Bloqueados: " + bloqueados.size() +
            "\n  │  Scanners  : " + sc +
            "\n  │  BruteForce: " + br +
            "\n  │  Credenciais: " + cr +
            "\n  └─────────────────────────────────────┘" + RESET);
    }

    // ========== SERVIDOR ==========
    static void iniciaServidor(int porta) {
        System.out.println(VERDE + "  [+] " + RESET + nomeServico(porta) + " na porta " + AMAR + porta + RESET);
        try (ServerSocket srv = new ServerSocket(porta)) {
            srv.setReuseAddress(true);
            srv.setSoTimeout(0);
            while (true) {
                try {
                    Socket cliente = srv.accept();
                    cliente.setSoTimeout(CONN_TIMEOUT);
                    // Proteção: rejeita se pool estiver saturado
                    if (((ThreadPoolExecutor)pool).getActiveCount() >= MAX_CONN - 2) {
                        silentClose(cliente);
                        continue;
                    }
                    pool.submit(() -> trataConexao(cliente, porta));
                } catch (IOException ignored) {}
            }
        } catch (IOException e) {
            System.out.println(VERM + "  [!] Porta " + porta + ": " + e.getMessage() + RESET);
        }
    }

    // ========== TRATA CONEXAO ==========
    static void trataConexao(Socket cliente, int porta) {
        String ip = cliente.getInetAddress().getHostAddress();

        // Proteção 1: blocklist
        if (bloqueados.contains(ip)) { totalBloq.incrementAndGet(); silentClose(cliente); return; }

        // Proteção 2: rate limit
        int tentativas = contadorIP.merge(ip, 1, Integer::sum);
        if (tentativas > RATE_LIM) {
            bloqueados.add(ip); totalBloq.incrementAndGet();
            salvaBloqueados();
            System.out.println(VERM + NEG + "  [BLOQ] " + RESET + VERM + ip + " (" + tentativas + "x)" + RESET);
            salvaEventoTXT(ip, "BLOQUEADO rate limit (" + tentativas + "x)");
            silentClose(cliente); return;
        }

        // Proteção 3: cooldown 500ms
        long agora = System.currentTimeMillis();
        Long ult = ultimaConn.put(ip, agora);
        if (ult != null && (agora - ult) < 500) { silentClose(cliente); return; }

        totalConn.incrementAndGet();
        String horario = LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss"));
        String servico = nomeServico(porta);

        try (
            BufferedReader entrada = new BufferedReader(new InputStreamReader(cliente.getInputStream()));
            PrintWriter saida = new PrintWriter(new BufferedOutputStream(cliente.getOutputStream()), true)
        ) {
            StringBuilder cabecalhos = new StringBuilder();
            String metodo = "UNKNOWN", rota = "/";
            int contentLength = 0, hdrsBytes = 0;

            // Proteção 4: limite de tamanho dos headers
            try {
                boolean primeira = true;
                String linha;
                while ((linha = entrada.readLine()) != null && !linha.isEmpty()) {
                    hdrsBytes += linha.length() + 2;
                    if (hdrsBytes > MAX_HDRS) break;
                    cabecalhos.append(linha).append("\n");
                    if (primeira) {
                        String[] p = linha.split(" ");
                        if (p.length >= 2) { metodo = sanitiza(p[0], 10); rota = sanitiza(p[1], 200); }
                        primeira = false;
                    }
                    if (linha.toLowerCase().startsWith("content-length:")) {
                        try { contentLength = Integer.parseInt(linha.substring(15).trim()); }
                        catch (NumberFormatException ignored) {}
                    }
                }
            } catch (IOException ignored) {}

            // Proteção 5: limite de tamanho do body
            StringBuilder body = new StringBuilder();
            int limite = Math.min(contentLength, MAX_BODY);
            if (limite > 0) {
                try {
                    char[] buf = new char[limite];
                    int lido = entrada.read(buf, 0, limite);
                    if (lido > 0) body.append(buf, 0, lido);
                } catch (IOException ignored) {}
            }

            String bodyStr   = body.toString();
            String dadosFull = cabecalhos + "\n" + bodyStr;

            // Proteção 6: detecta injeção de CRLF nos headers
            if (cabecalhos.toString().contains("\r\n\r\n")) {
                salvaEventoTXT(ip, "CRLF INJECTION attempt detectado");
                silentClose(cliente); return;
            }

            // Envia banner falso
            try { saida.print(bannerFalso(porta, rota, ip)); saida.flush(); }
            catch (Exception ignored) {}

            // Extrai User-Agent
            String ua = "";
            for (String h : cabecalhos.toString().split("\n")) {
                if (h.toLowerCase().startsWith("user-agent:")) {
                    ua = h.substring(11).trim().toLowerCase(); break;
                }
            }

            // Proteção 7: detecta scanners
            boolean scanner = ua.contains("nmap") || ua.contains("masscan") ||
                               ua.contains("zgrab") || ua.contains("nikto") ||
                               ua.contains("sqlmap") || ua.contains("shodan") ||
                               ua.contains("dirbuster") || ua.contains("gobuster") ||
                               ua.contains("hydra") || ua.contains("burpsuite") ||
                               ua.contains("metasploit") || ua.contains("zmap") ||
                               ua.contains("wfuzz") || ua.contains("acunetix") ||
                               ua.contains("openvas") || ua.contains("nessus");

            // Proteção 8: detecta tentativas de path traversal
            boolean pathTraversal = rota.contains("../") || rota.contains("..\\") ||
                                     rota.contains("%2e%2e") || rota.contains("%252e");
            if (pathTraversal) {
                salvaAmeaca(ip, horario, "PATH TRAVERSAL: " + rota);
                scanner = true;
            }

            // Proteção 9: detecta SQL injection no body
            String bodyLow = bodyStr.toLowerCase();
            boolean sqlInject = bodyLow.contains("union select") || bodyLow.contains("or 1=1") ||
                                  bodyLow.contains("drop table") || bodyLow.contains("insert into") ||
                                  bodyLow.contains("exec(") || bodyLow.contains("xp_cmdshell");
            if (sqlInject) salvaAmeaca(ip, horario, "SQL INJECTION attempt: " + bodyStr.substring(0, Math.min(200, bodyStr.length())));

            // Proteção 10: detecta XSS
            boolean xss = bodyLow.contains("<script") || bodyLow.contains("javascript:") ||
                           bodyLow.contains("onerror=") || bodyLow.contains("onload=");
            if (xss) salvaAmeaca(ip, horario, "XSS attempt: " + bodyStr.substring(0, Math.min(200, bodyStr.length())));

            // Proteção 11: brute force por janela de tempo
            List<Long> janela = bruteForce.computeIfAbsent(ip,
                k -> Collections.synchronizedList(new ArrayList<>()));
            janela.add(agora);
            janela.removeIf(t -> agora - t > BRUTE_WIN);
            boolean bruteDetectado = janela.size() >= 5;
            if (bruteDetectado && !bloqueados.contains(ip)) {
                System.out.println(MAG + NEG + "  [BRUTE] " + RESET + MAG + ip + " (" + janela.size() + "/60s)" + RESET);
                salvaEventoTXT(ip, "BRUTE FORCE (" + janela.size() + " req/60s)");
            }

            // Extrai credenciais
            String usuario = "", senha = "";
            if (rota.startsWith("/api/v1/") && bodyStr.contains("{")) {
                servico = "API (" + metodo + ")";
                usuario = "[JSON]";
                senha   = bodyStr.trim().substring(0, Math.min(500, bodyStr.trim().length()));
            } else if (bodyStr.contains("username=") && bodyStr.contains("password=")) {
                for (String param : bodyStr.split("&")) {
                    try {
                        if (param.startsWith("username="))
                            usuario = sanitiza(URLDecoder.decode(param.substring(9), "UTF-8"), 100);
                        if (param.startsWith("password="))
                            senha = sanitiza(URLDecoder.decode(param.substring(9), "UTF-8"), 100);
                    } catch (Exception ignored) {}
                }
            } else {
                String[] cred = extraiCredenciais(dadosFull);
                usuario = cred[0]; senha = cred[1];
            }

            boolean relevante = !bodyStr.isEmpty() || !usuario.isEmpty() ||
                                  porta != 8080 || !rota.equals("/") ||
                                  scanner || bruteDetectado || sqlInject || xss;
            if (!relevante) { silentClose(cliente); return; }

            // Geolocalização com lat/lon para o mapa
            String[] geo = geolocalizaIP(ip);
            String pais = geo[0], cidade = geo[1], org = geo[2];
            String lat  = geo[3], lon = geo[4];

            // Tipo de evento
            String tipo;
            if (sqlInject || xss)     tipo = "EXPLOIT";
            else if (scanner)          tipo = "SCANNER";
            else if (bruteDetectado)   tipo = "BRUTE";
            else if (!usuario.isEmpty()) tipo = "CREDENCIAL";
            else                       tipo = "NORMAL";

            // Log terminal
            String cor = tipo.equals("EXPLOIT") ? VERM :
                         tipo.equals("SCANNER") ? VERM :
                         tipo.equals("BRUTE")   ? MAG  :
                         tipo.equals("CREDENCIAL") ? AMAR : DIM;
            System.out.println("\n" + cor + NEG + "  [" + tipo + "] " + RESET);
            System.out.println(DIM + "  ┌──────────────────────────────────────" + RESET);
            System.out.println("  │ " + AMAR + "Servico  " + RESET + servico + (porta != 8080 ? "" : " -> " + rota));
            System.out.println("  │ " + AMAR + "IP       " + RESET + ip);
            System.out.println("  │ " + AMAR + "Local    " + RESET + cidade + " / " + pais);
            System.out.println("  │ " + AMAR + "Provedor " + RESET + org);
            System.out.println("  │ " + AMAR + "Coords   " + RESET + lat + ", " + lon);
            System.out.println("  │ " + AMAR + "Horario  " + RESET + horario);
            System.out.println("  │ " + AMAR + "Tentativ " + RESET + tentativas + "x");
            if (!usuario.isEmpty())
                System.out.println("  │ " + VERM + NEG + "Login    " + RESET + VERM + usuario + (senha.isEmpty() ? "" : " / " + senha) + RESET);
            System.out.println(DIM + "  └──────────────────────────────────────" + RESET);

            // Salva
            String payloadLog = bodyStr.isEmpty() ? "(sem payload)" :
                bodyStr.substring(0, Math.min(MAX_PAYLOAD_LOG, bodyStr.length()));

            synchronized (conexoes) {
                if (conexoes.size() >= MAX_LOG) conexoes.remove(0);
                conexoes.add(new String[]{
                    horario, ip, pais, cidade, org, servico, rota,
                    usuario, senha, payloadLog, tipo,
                    String.valueOf(tentativas), lat, lon
                });
            }

            salvaLogTXT(ip, horario, servico, porta, usuario, senha, pais, cidade, org, lat, lon, dadosFull);
            geraRelatorioHTML();

        } catch (Exception ignored) {
        } finally {
            silentClose(cliente);
        }
    }

    // ========== GEOLOCALIZAÇÃO COM LAT/LON ==========
    static String[] geolocalizaIP(String ip) {
        if (ip.startsWith("127.") || ip.startsWith("192.168.") ||
            ip.startsWith("10.")  || ip.contains(":"))
            return new String[]{"Brasil", "Itabuna", "Rede Local", "-14.7869", "-39.2800"};

        if (cacheGeo.containsKey(ip)) return cacheGeo.get(ip);

        try {
            HttpClient hc = HttpClient.newBuilder()
                .connectTimeout(java.time.Duration.ofSeconds(3)).build();
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://ip-api.com/json/" + ip + "?fields=country,city,org,lat,lon"))
                .timeout(java.time.Duration.ofSeconds(3)).build();
            HttpResponse<String> resp = hc.send(req, HttpResponse.BodyHandlers.ofString());
            String b = resp.body();
            String[] res = new String[]{
                def(extraiJson(b, "country"), "?"),
                def(extraiJson(b, "city"),    "?"),
                def(extraiJson(b, "org"),     "?"),
                def(extraiJsonNum(b, "lat"),  "0"),
                def(extraiJsonNum(b, "lon"),  "0")
            };
            cacheGeo.put(ip, res);
            return res;
        } catch (Exception e) {
            return new String[]{"?", "?", "?", "0", "0"};
        }
    }

    static String def(String v, String fallback) { return (v == null || v.isEmpty()) ? fallback : v; }

    static String extraiJson(String json, String campo) {
        String chave = "\"" + campo + "\":\"";
        int i = json.indexOf(chave);
        if (i < 0) return "";
        i += chave.length();
        int f = json.indexOf("\"", i);
        return f < 0 ? "" : json.substring(i, f);
    }

    static String extraiJsonNum(String json, String campo) {
        String chave = "\"" + campo + "\":";
        int i = json.indexOf(chave);
        if (i < 0) return "";
        i += chave.length();
        int f = i;
        while (f < json.length() && (Character.isDigit(json.charAt(f)) ||
               json.charAt(f) == '.' || json.charAt(f) == '-')) f++;
        return json.substring(i, f);
    }

    // ========== BLOCKLIST ==========
    static void carregaBloqueados() {
        File f = new File(BLOCKED_FILE);
        if (!f.exists()) return;
        try (BufferedReader br = new BufferedReader(new FileReader(f))) {
            String linha; int count = 0;
            while ((linha = br.readLine()) != null)
                if (!linha.isBlank() && isValidIP(linha.trim())) {
                    bloqueados.add(linha.trim()); count++;
                }
            if (count > 0)
                System.out.println(AMAR + "  [!] " + count + " IPs carregados." + RESET);
        } catch (IOException ignored) {}
    }

    static void salvaBloqueados() {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(BLOCKED_FILE))) {
            for (String ip : bloqueados) { bw.write(ip); bw.newLine(); }
        } catch (IOException ignored) {}
    }

    static boolean isValidIP(String ip) {
        return ip.matches("^((25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(25[0-5]|2[0-4]\\d|[01]?\\d\\d?)$");
    }

    static String sanitiza(String input, int maxLen) {
        if (input == null) return "";
        return input.replaceAll("[\\x00-\\x1F\\x7F]", "")
                    .substring(0, Math.min(input.length(), maxLen));
    }

    // ========== ROTAÇÃO DE LOG ==========
    static void rotacionaLog() {
        for (String logFile : new String[]{LOG_TXT, LOG_THREATS}) {
            File f = new File(logFile);
            if (!f.exists() || f.length() < MAX_LOG_SIZE) continue;
            String ts = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmm"));
            f.renameTo(new File(logFile.replace(".txt", "_" + ts + ".txt")));
        }
    }

    // ========== PDF ==========
    static void geraRelatorioPDF() {
        String ts  = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmm"));
        String pdf = "honeypot_report_" + ts + ".pdf";
        try {
            Process p = new ProcessBuilder("wkhtmltopdf", "--quiet", LOG_HTML, pdf)
                .redirectErrorStream(true).start();
            if (p.waitFor() == 0)
                System.out.println(VERDE + "  [+] PDF: " + pdf + RESET);
            else
                System.out.println(AMAR + "  [!] Instale: sudo apt install wkhtmltopdf" + RESET);
        } catch (Exception e) {
            System.out.println(AMAR + "  [!] PDF indisponivel." + RESET);
        }
    }

    // ========== PAINEL ==========
    static void iniciaPainelControle() {
        new Thread(() -> {
            Scanner sc = new Scanner(System.in);
            System.out.println(CIANO + "  Digite \'help\' para comandos." + RESET);
            while (true) {
                System.out.print(NEG + CIANO + "\n  shutdown> " + RESET);
                String cmd = sc.nextLine().trim().toLowerCase();
                switch (cmd) {
                    case "help" -> System.out.println(CIANO +
                        "\n  stats | bloqueados | limpar | pdf | unblock X | block X | sair" + RESET);
                    case "stats"      -> printStats();
                    case "pdf"        -> geraRelatorioPDF();
                    case "limpar"     -> { conexoes.clear(); System.out.println(VERDE + "  Limpo." + RESET); }
                    case "bloqueados" -> {
                        if (bloqueados.isEmpty()) System.out.println("  Nenhum.");
                        else bloqueados.forEach(ip -> System.out.println("  " + VERM + ip + RESET));
                    }
                    case "sair" -> { salvaBloqueados(); System.exit(0); }
                    default -> {
                        if (cmd.startsWith("unblock ")) {
                            String ipx = cmd.substring(8).trim();
                            bloqueados.remove(ipx); contadorIP.remove(ipx); salvaBloqueados();
                            System.out.println(VERDE + "  Desbloqueado: " + ipx + RESET);
                        } else if (cmd.startsWith("block ")) {
                            String ipx = cmd.substring(6).trim();
                            if (isValidIP(ipx)) { bloqueados.add(ipx); salvaBloqueados(); System.out.println(VERM + "  Bloqueado: " + ipx + RESET); }
                            else System.out.println("  IP invalido.");
                        } else System.out.println("  Desconhecido. Digite \'help\'.");
                    }
                }
            }
        }, "painel").start();
    }

    // ========== HTML REPORT ==========
    static void geraRelatorioHTML() {
        try (PrintWriter pw = new PrintWriter(new FileWriter(LOG_HTML))) {
            pw.print(htmlHead());
            pw.println("<body>");
            pw.println("<div id=\'app\'>");

            // Sidebar
            pw.println("<aside class=\'sidebar\'>");
            pw.println("<div class=\'logo-wrap\'><img src=\'data:image/jpeg;base64,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AAACAAoAAAAAAAAAAAAAIACgAAAAAAAAAAAgAKAAAAAAAAACAAoAAAIACgAAAAAgAAAKAAAAACAIkjwUSAAAAAAAAAAAAAgAKAAACAAAAoAIAAACgAAAgAKACAAAAAAoAAAIACgAAAgAAAKACAAoAIAAACgAAAAAgAAAKIk2SAAAAAAAAIACgAAAgAKAAAAAAAAACAAAAAAoAAAAAAAAAAAAAAAIACgAAAgAAAKAAAAAAAAACAAoAIACgAAACDckiASAAAAAAAAAAAgAKAAAAAAAAAAACAAoAIACgAACNgSAAAgAKAAACAAAAAAoAAAIAAACgI2SAAAAgAKAAAAAAAAAAAAAAAAIlIAAAAIACgAAjZIAAAAAAAAAAAAAAgAKAAAAACAAoAAAAAAAAAIAI2USAAAAAgAKAAAAIlIAAAAAAACISAAAAAAAAAAAAAAACJBIAAAAAAAAAAAAACN0o2BIAAAAAAAAAAAACAAAAoAAAAAAAAAIAAACgAAAAAAAAAAAgAAAAAKAAAhIACAAoI2SAjZIAAAAAAAI2SAAAAAAAAAAAAAAAAAiEgAAAAAACNkgAAAAACNwSAAAAAAjZIAAAAAACNkgAAAjZIAAghIKIhIAISAhKNjYEyjcnwASAAAAAAAgAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAoAAAAAAAAAAAAAAAAAIACgjdIAAgAKAAACAAoAAiSABIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIABIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI3BIAAAAAAAAAAAAAAAAAISgB/9k=\' class=\'logo-img\'/></div>");
            pw.println("<nav>");
            pw.println("<a class=\'nav-item active\' onclick=\'showTab(\"dashboard\")\'>Dashboard</a>");
            pw.println("<a class=\'nav-item\' onclick=\'showTab(\"conexoes\")\'>Conexoes</a>");
            pw.println("<a class=\'nav-item\' onclick=\'showTab(\"mapa\")\'>Mapa</a>");
            pw.println("<a class=\'nav-item\' onclick=\'showTab(\"ameacas\")\'>Ameacas</a>");
            pw.println("<a class=\'nav-item\' onclick=\'showTab(\"bloqueados\")\'>Bloqueados</a>");
            pw.println("</nav>");
            pw.println("<div class=\'sb-footer\'>SHUTDOWN SEC<br/>v5.0</div>");
            pw.println("</aside>");

            // Main
            pw.println("<main class=\'main\'>");
            pw.println("<header class=\'topbar\'>");
            pw.println("<div class=\'topbar-title\'>HONEYPOT INTELLIGENCE PLATFORM</div>");
            pw.println("<div class=\'topbar-right\'>");
            pw.println("<span class=\'live-dot\'></span><span class=\'live-txt\'>LIVE</span>");
            pw.println("<span class=\'topbar-time\'>" +
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss")) + "</span>");
            pw.println("</div></header>");

            long scanners = conexoes.stream().filter(c -> "SCANNER".equals(c[10])).count();
            long brutes   = conexoes.stream().filter(c -> "BRUTE".equals(c[10])).count();
            long comCred  = conexoes.stream().filter(c -> !c[7].isEmpty()).count();
            long exploits = conexoes.stream().filter(c -> "EXPLOIT".equals(c[10])).count();

            // ===== TAB DASHBOARD =====
            pw.println("<div id=\'tab-dashboard\' class=\'tab active\'>");
            pw.println("<div class=\'stats\'>");
            pw.println(card("CONEXOES",    String.valueOf(conexoes.size()), "c-blue",   "CONNECTION"));
            pw.println(card("BLOQUEADOS",  String.valueOf(bloqueados.size()), "c-red",  "BLOCKED"));
            pw.println(card("SCANNERS",    String.valueOf(scanners), "c-gray",          "SCAN"));
            pw.println(card("BRUTE FORCE", String.valueOf(brutes),  "c-gray",           "BRUTE"));
            pw.println(card("EXPLOITS",    String.valueOf(exploits), "c-red",           "EXPLOIT"));
            pw.println(card("CREDENCIAIS", String.valueOf(comCred), "c-blue",           "CREDENTIAL"));
            pw.println("</div>");

            // Charts row
            Map<String,Long> porServico = new LinkedHashMap<>();
            synchronized (conexoes) {
                conexoes.stream()
                    .collect(java.util.stream.Collectors.groupingBy(
                        c -> c[5].split(" ")[0], java.util.stream.Collectors.counting()))
                    .entrySet().stream()
                    .sorted(Map.Entry.<String,Long>comparingByValue().reversed())
                    .forEach(e -> porServico.put(e.getKey(), e.getValue()));
            }
            Map<String,Long> porPais = new LinkedHashMap<>();
            synchronized (conexoes) {
                conexoes.stream()
                    .collect(java.util.stream.Collectors.groupingBy(c -> c[2], java.util.stream.Collectors.counting()))
                    .entrySet().stream()
                    .sorted(Map.Entry.<String,Long>comparingByValue().reversed())
                    .limit(8)
                    .forEach(e -> porPais.put(e.getKey(), e.getValue()));
            }

            pw.println("<div class=\'charts-row\'>");

            // Chart servicos
            pw.println("<div class=\'chart-box\'><div class=\'chart-title\'>ATIVIDADE POR SERVICO</div>");
            if (!porServico.isEmpty()) {
                long maxV = porServico.values().stream().mapToLong(v->v).max().orElse(1);
                pw.println("<div class=\'bar-chart\'>");
                porServico.forEach((svc, qtd) -> {
                    int pct = (int)(qtd * 100 / maxV);
                    pw.println("<div class=\'bar-row\'>" +
                        "<span class=\'bar-lbl\'>" + esc(svc) + "</span>" +
                        "<div class=\'bar-track\'><div class=\'bar-fill\' style=\'width:" + pct + "%\'></div></div>" +
                        "<span class=\'bar-num\'>" + qtd + "</span></div>");
                });
                pw.println("</div>");
            } else pw.println("<p class=\'empty\'>Aguardando conexoes...</p>");
            pw.println("</div>");

            // Chart paises
            pw.println("<div class=\'chart-box\'><div class=\'chart-title\'>ORIGEM POR PAIS</div>");
            if (!porPais.isEmpty()) {
                long maxP = porPais.values().stream().mapToLong(v->v).max().orElse(1);
                pw.println("<div class=\'bar-chart\'>");
                porPais.forEach((pais, qtd) -> {
                    int pct = (int)(qtd * 100 / maxP);
                    pw.println("<div class=\'bar-row\'>" +
                        "<span class=\'bar-lbl\'>" + esc(pais) + "</span>" +
                        "<div class=\'bar-track\'><div class=\'bar-fill bar-alt\' style=\'width:" + pct + "%\'></div></div>" +
                        "<span class=\'bar-num\'>" + qtd + "</span></div>");
                });
                pw.println("</div>");
            } else pw.println("<p class=\'empty\'>Aguardando conexoes...</p>");
            pw.println("</div></div>"); // charts-row

            // Timeline
            pw.println("<div class=\'section-box\'><div class=\'chart-title\'>ULTIMAS DETECCOES</div>");
            pw.println("<div class=\'timeline\'>");
            synchronized (conexoes) {
                List<String[]> copia = new ArrayList<>(conexoes);
                Collections.reverse(copia);
                copia.stream().limit(8).forEach(c -> {
                    String dotCls = "EXPLOIT".equals(c[10]) || "SCANNER".equals(c[10]) ? "dot-red" :
                                    "BRUTE".equals(c[10])   ? "dot-yellow" :
                                    !c[7].isEmpty()         ? "dot-blue" : "dot-gray";
                    pw.println("<div class=\'tl-item\'>" +
                        "<div class=\'tl-dot " + dotCls + "\'></div>" +
                        "<div class=\'tl-body\'>" +
                        "<span class=\'tl-time\'>" + c[0] + "</span>" +
                        "<span class=\'tl-ip\'>" + c[1] + "</span>" +
                        "<span class=\'tl-loc\'>" + esc(c[3]) + " / " + esc(c[2]) + "</span>" +
                        "<span class=\'tl-svc\'>" + esc(c[5]) + "</span>" +
                        "<span class=\'badge t-" + c[10].toLowerCase() + "\'>" + c[10] + "</span>" +
                        "</div></div>");
                });
            }
            pw.println("</div></div></div>"); // timeline + section-box + tab-dashboard

            // ===== TAB CONEXOES =====
            pw.println("<div id=\'tab-conexoes\' class=\'tab\'>");
            pw.println("<div class=\'toolbar\'>");
            pw.println("<input class=\'search-box\' id=\'searchBox\' onkeyup=\'filtrar()\' placeholder=\'Filtrar por IP, pais, servico...\'>");
            pw.println("<select class=\'sel\' id=\'filterTipo\' onchange=\'filtrar()\'>" +
                "<option value=\'\'>Todos</option>" +
                "<option value=\'SCANNER\'>Scanner</option>" +
                "<option value=\'BRUTE\'>Brute Force</option>" +
                "<option value=\'EXPLOIT\'>Exploit</option>" +
                "<option value=\'CREDENCIAL\'>Credencial</option>" +
                "<option value=\'NORMAL\'>Normal</option>" +
                "</select>");
            pw.println("</div>");
            pw.println("<div class=\'table-wrap\'><table id=\'tbl\'>");
            pw.println("<thead><tr><th>HORARIO</th><th>IP</th><th>PAIS</th><th>CIDADE</th>" +
                "<th>PROVEDOR</th><th>SERVICO</th><th>ROTA</th><th>TIPO</th>" +
                "<th>CREDENCIAIS</th><th>TENTATIVAS</th><th>MAPA</th><th>PAYLOAD</th></tr></thead><tbody>");

            synchronized (conexoes) {
                List<String[]> copia = new ArrayList<>(conexoes);
                Collections.reverse(copia);
                for (String[] c : copia) {
                    boolean temCred = !c[7].isEmpty();
                    String rowCls = "EXPLOIT".equals(c[10])   ? "row-exploit" :
                                    "SCANNER".equals(c[10])   ? "row-scanner" :
                                    "BRUTE".equals(c[10])     ? "row-brute"   :
                                    temCred                   ? "row-cred"    : "";
                    String credHtml = temCred ?
                        "<span class=\'cred\'>" + esc(c[7]) + (c[8].isEmpty() ? "" : " / " + esc(c[8])) + "</span>" :
                        "<span class=\'dim\'>—</span>";
                    // Link Google Maps com lat/lon
                    String lat = c[12], lon = c[13];
                    String mapLink = (!lat.equals("0") && !lon.equals("0")) ?
                        "<a class=\'map-link\' href=\'https://maps.google.com/?q=" + lat + "," + lon +
                        "\' target=\'_blank\'>📍 Ver Mapa</a>" :
                        "<span class=\'dim\'>local</span>";

                    pw.println("<tr class=\'" + rowCls + "\' data-tipo=\'" + c[10] + "\' data-cred=\'" + (temCred ? "CREDENCIAL" : "") + "\'>" +
                        "<td class=\'mono\'>" + c[0] + "</td>" +
                        "<td class=\'mono ip\'>" + c[1] + "</td>" +
                        "<td>" + esc(c[2]) + "</td>" +
                        "<td>" + esc(c[3]) + "</td>" +
                        "<td class=\'dim\'>" + esc(c[4]) + "</td>" +
                        "<td><span class=\'svc-badge " + svcClass(c[5]) + "\'>" + esc(c[5]) + "</span></td>" +
                        "<td class=\'mono dim\'>" + esc(c[6]) + "</td>" +
                        "<td><span class=\'badge t-" + c[10].toLowerCase() + "\'>" + c[10] + "</span></td>" +
                        "<td>" + credHtml + "</td>" +
                        "<td class=\'center mono\'>" + c[11] + "x</td>" +
                        "<td>" + mapLink + "</td>" +
                        "<td><details><summary>ver</summary><pre>" + esc(c[9]) + "</pre></details></td>" +
                        "</tr>");
                }
            }
            pw.println("</tbody></table></div></div>");

            // ===== TAB MAPA =====
            // Coleta pontos únicos para o mapa
            StringBuilder mapaPoints = new StringBuilder();
            synchronized (conexoes) {
                conexoes.stream()
                    .filter(c -> !c[12].equals("0") && !c[13].equals("0"))
                    .forEach(c -> {
                        String color = "EXPLOIT".equals(c[10]) ? "#cc2200" :
                                       "SCANNER".equals(c[10]) ? "#884400" :
                                       "BRUTE".equals(c[10])   ? "#664488" :
                                       !c[7].isEmpty()         ? "#336688" : "#334455";
                        mapaPoints.append("{lat:").append(c[12])
                            .append(",lon:").append(c[13])
                            .append(",ip:\'").append(esc(c[1])).append("\'")
                            .append(",city:\'").append(esc(c[3])).append("\'")
                            .append(",country:\'").append(esc(c[2])).append("\'")
                            .append(",tipo:\'").append(esc(c[10])).append("\'")
                            .append(",time:\'").append(esc(c[0])).append("\'")
                            .append(",color:\'").append(color).append("\'")
                            .append("},");
                    });
            }

            pw.println("<div id=\'tab-mapa\' class=\'tab\'>");
            pw.println("<div class=\'section-box\'>");
            pw.println("<div class=\'chart-title\'>MAPA DE ORIGEM DAS CONEXOES</div>");
            pw.println("<div id=\'map-container\'>");
            pw.println("<div id=\'map-svg-wrap\'>");
            pw.println("<svg id=\'world-map\' viewBox=\'0 0 1000 500\' xmlns=\'http://www.w3.org/2000/svg\'>");
            // Simplified world outline paths
            pw.println("<rect width=\'1000\' height=\'500\' fill=\'#0a0c0f\'/>");
            pw.println("<text x=\'500\' y=\'250\' text-anchor=\'middle\' fill=\'#1a2233\' font-size=\'18\'>MAPA GLOBAL DE AMEACAS</text>");
            pw.println("</svg>");
            pw.println("<canvas id=\'mapCanvas\' width=\'1000\' height=\'500\'></canvas>");
            pw.println("</div>");
            pw.println("<div id=\'map-legend\'>" +
                "<span class=\'leg-item\'><span class=\'leg-dot\' style=\'background:#cc2200\'></span>Exploit</span>" +
                "<span class=\'leg-item\'><span class=\'leg-dot\' style=\'background:#884400\'></span>Scanner</span>" +
                "<span class=\'leg-item\'><span class=\'leg-dot\' style=\'background:#664488\'></span>Brute</span>" +
                "<span class=\'leg-item\'><span class=\'leg-dot\' style=\'background:#336688\'></span>Credencial</span>" +
                "<span class=\'leg-item\'><span class=\'leg-dot\' style=\'background:#334455\'></span>Normal</span>" +
                "</div>");
            pw.println("<div id=\'map-list\'><div class=\'chart-title\'>CONEXOES COM LOCALIZACAO</div>");
            pw.println("<div class=\'map-entries\'>");
            synchronized (conexoes) {
                List<String[]> copia = new ArrayList<>(conexoes);
                Collections.reverse(copia);
                copia.stream().filter(c -> !c[12].equals("0")).limit(20).forEach(c -> {
                    String mapUrl = "https://maps.google.com/?q=" + c[12] + "," + c[13];
                    pw.println("<div class=\'map-entry\'>" +
                        "<div class=\'me-left\'>" +
                        "<span class=\'me-ip mono ip\'>" + esc(c[1]) + "</span>" +
                        "<span class=\'me-loc\'>" + esc(c[3]) + ", " + esc(c[2]) + "</span>" +
                        "<span class=\'me-org dim\'>" + esc(c[4]) + "</span>" +
                        "</div>" +
                        "<div class=\'me-right\'>" +
                        "<span class=\'badge t-" + c[10].toLowerCase() + "\'>" + c[10] + "</span>" +
                        "<a class=\'map-link-btn\' href=\'" + mapUrl + "\' target=\'_blank\'>📍 Google Maps</a>" +
                        "</div></div>");
                });
            }
            pw.println("</div></div></div></div></div>");

            // ===== TAB AMEACAS =====
            pw.println("<div id=\'tab-ameacas\' class=\'tab\'>");
            pw.println("<div class=\'charts-row\'>");

            // Top IPs
            pw.println("<div class=\'chart-box\'><div class=\'chart-title\'>TOP IPS MAIS ATIVOS</div>");
            Map<String,Long> topIPs = new LinkedHashMap<>();
            synchronized (conexoes) {
                conexoes.stream()
                    .collect(java.util.stream.Collectors.groupingBy(c -> c[1], java.util.stream.Collectors.counting()))
                    .entrySet().stream()
                    .sorted(Map.Entry.<String,Long>comparingByValue().reversed())
                    .limit(10)
                    .forEach(e -> topIPs.put(e.getKey(), e.getValue()));
            }
            if (!topIPs.isEmpty()) {
                long maxIP = topIPs.values().stream().mapToLong(v->v).max().orElse(1);
                pw.println("<div class=\'bar-chart\'>");
                topIPs.forEach((ipAddr, qtd) -> {
                    int pct = (int)(qtd * 100 / maxIP);
                    pw.println("<div class=\'bar-row\'>" +
                        "<span class=\'bar-lbl mono ip\'>" + esc(ipAddr) + "</span>" +
                        "<div class=\'bar-track\'><div class=\'bar-fill bar-red\' style=\'width:" + pct + "%\'></div></div>" +
                        "<span class=\'bar-num\'>" + qtd + "</span></div>");
                });
                pw.println("</div>");
            } else pw.println("<p class=\'empty\'>Sem dados.</p>");
            pw.println("</div>");

            // Distribuição tipos
            pw.println("<div class=\'chart-box\'><div class=\'chart-title\'>DISTRIBUICAO POR TIPO</div>");
            long total = conexoes.size();
            if (total > 0) {
                String[][] tiposData = {
                    {"Normal",    String.valueOf(conexoes.stream().filter(c -> "NORMAL".equals(c[10])).count()),    "#334455"},
                    {"Scanner",   String.valueOf(scanners),  "#884400"},
                    {"Brute",     String.valueOf(brutes),    "#664488"},
                    {"Credencial",String.valueOf(comCred),   "#336688"},
                    {"Exploit",   String.valueOf(exploits),  "#cc2200"}
                };
                pw.println("<div class=\'dist-list\'>");
                for (String[] td : tiposData) {
                    long qtd = Long.parseLong(td[1]);
                    int pct = (int)(qtd * 100 / total);
                    pw.println("<div class=\'dist-row\'>" +
                        "<span class=\'dist-dot\' style=\'background:" + td[2] + "\'></span>" +
                        "<span class=\'dist-lbl\'>" + td[0] + "</span>" +
                        "<div class=\'bar-track\'><div class=\'bar-fill\' style=\'width:" + pct + "%;background:" + td[2] + "\'></div></div>" +
                        "<span class=\'dist-pct\'>" + pct + "%</span>" +
                        "</div>");
                }
                pw.println("</div>");
            } else pw.println("<p class=\'empty\'>Sem dados.</p>");
            pw.println("</div></div>"); // charts-row ameacas

            // Tabela só exploits + scanners
            pw.println("<div class=\'section-box\'><div class=\'chart-title\'>AMEACAS CRITICAS</div>");
            pw.println("<div class=\'table-wrap\'><table>");
            pw.println("<thead><tr><th>HORARIO</th><th>IP</th><th>PAIS</th><th>TIPO</th><th>SERVICO</th><th>MAPA</th></tr></thead><tbody>");
            synchronized (conexoes) {
                List<String[]> copia = new ArrayList<>(conexoes);
                Collections.reverse(copia);
                copia.stream()
                    .filter(c -> "EXPLOIT".equals(c[10]) || "SCANNER".equals(c[10]) || "BRUTE".equals(c[10]))
                    .limit(50)
                    .forEach(c -> {
                        String mapUrl = (!c[12].equals("0")) ?
                            "<a class=\'map-link\' href=\'https://maps.google.com/?q=" + c[12] + "," + c[13] + "\' target=\'_blank\'>📍 Maps</a>" :
                            "—";
                        pw.println("<tr class=\'row-" + c[10].toLowerCase() + "\'>" +
                            "<td class=\'mono\'>" + c[0] + "</td>" +
                            "<td class=\'mono ip\'>" + c[1] + "</td>" +
                            "<td>" + esc(c[2]) + "</td>" +
                            "<td><span class=\'badge t-" + c[10].toLowerCase() + "\'>" + c[10] + "</span></td>" +
                            "<td>" + esc(c[5]) + "</td>" +
                            "<td>" + mapUrl + "</td></tr>");
                    });
            }
            pw.println("</tbody></table></div></div></div>");

            // ===== TAB BLOQUEADOS =====
            pw.println("<div id=\'tab-bloqueados\' class=\'tab\'>");
            pw.println("<div class=\'section-box\'><div class=\'chart-title\'>IPS BLOQUEADOS (" + bloqueados.size() + ")</div>");
            if (bloqueados.isEmpty()) {
                pw.println("<p class=\'empty\'>Nenhum IP bloqueado.</p>");
            } else {
                pw.println("<div class=\'blocked-grid\'>");
                bloqueados.forEach(ipB ->
                    pw.println("<div class=\'blocked-item\'><span class=\'mono ip\'>" + esc(ipB) + "</span></div>"));
                pw.println("</div>");
            }
            pw.println("</div></div>");

            pw.println("</main></div>"); // main + app
            pw.print(htmlScripts(mapaPoints.toString()));
            pw.println("</body></html>");

        } catch (IOException e) {
            System.out.println(VERM + "  [!] HTML: " + e.getMessage() + RESET);
        }
    }

    static String card(String titulo, String valor, String cls, String lbl) {
        return "<div class=\'card " + cls + "\'>" +
               "<div class=\'card-lbl\'>" + lbl + "</div>" +
               "<div class=\'card-val\'>" + valor + "</div>" +
               "<div class=\'card-title\'>" + titulo + "</div>" +
               "</div>";
    }

    static String svcClass(String s) {
        s = s.toLowerCase();
        if (s.contains("ssh"))    return "svc-ssh";
        if (s.contains("ftp"))    return "svc-ftp";
        if (s.contains("mysql"))  return "svc-mysql";
        if (s.contains("api"))    return "svc-api";
        if (s.contains("telnet")) return "svc-telnet";
        if (s.contains("redis"))  return "svc-redis";
        if (s.contains("elastic"))return "svc-elastic";
        return "svc-http";
    }

    static String esc(String s) {
        if (s == null) return "";
        return s.replace("&","&amp;").replace("<","&lt;")
                .replace(">","&gt;").replace("\"","&quot;");
    }

    static String htmlHead() {
        return """
<!DOCTYPE html>
<html lang="pt-br">
<head>
<meta charset="UTF-8">
<title>Shutdown — Honeypot v5.0</title>
<style>
:root{
  --bg:#06080b;
  --bg2:#0a0d12;
  --bg3:#0e1218;
  --bg4:#121720;
  --border:#1c2230;
  --border2:#242d3d;
  --blue:#2a6496;
  --blue-dim:#1a3f60;
  --text:#8a9ab5;
  --text2:#5a6a80;
  --text-bright:#b0bdd0;
  --white:#d0dae8;
  --red:#8b2020;
  --red-dim:#5a1515;
  --mono:'Courier New',Courier,monospace;
  --sans:'Segoe UI',Arial,sans-serif;
  --sidebar:210px;
}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh;overflow-x:hidden;font-size:13px;}
#app{display:flex;min-height:100vh;}

/* SIDEBAR */
.sidebar{
  width:var(--sidebar);background:var(--bg2);
  border-right:1px solid var(--border);
  display:flex;flex-direction:column;
  position:fixed;top:0;left:0;height:100vh;z-index:100;
}
.logo-wrap{
  padding:24px 20px 20px;
  border-bottom:1px solid var(--border);
  display:flex;justify-content:center;
}
.logo-img{width:120px;height:auto;filter:brightness(0.9);}
nav{padding:12px 0;flex:1;}
.nav-item{
  display:block;padding:11px 20px;
  font-size:11px;letter-spacing:1.5px;
  color:var(--text2);cursor:pointer;
  border-left:2px solid transparent;
  transition:all .15s;text-decoration:none;
  text-transform:uppercase;
}
.nav-item:hover{color:var(--text-bright);background:rgba(42,100,150,.08);}
.nav-item.active{color:var(--blue);border-left-color:var(--blue);background:rgba(42,100,150,.12);}
.sb-footer{
  padding:14px 20px;font-size:9px;letter-spacing:2px;
  color:var(--text2);text-align:center;
  border-top:1px solid var(--border);line-height:1.8;
}

/* MAIN */
.main{margin-left:var(--sidebar);flex:1;display:flex;flex-direction:column;}
.topbar{
  display:flex;justify-content:space-between;align-items:center;
  padding:14px 24px;background:var(--bg2);
  border-bottom:1px solid var(--border);
  position:sticky;top:0;z-index:50;
}
.topbar-title{font-size:11px;font-weight:600;letter-spacing:3px;color:var(--text-bright);text-transform:uppercase;}
.topbar-right{display:flex;align-items:center;gap:12px;}
.live-dot{width:7px;height:7px;border-radius:50%;background:#2a6496;animation:pulse 2s infinite;}
@keyframes pulse{0%,100%{opacity:1;}50%{opacity:.4;}}
.live-txt{font-size:10px;letter-spacing:2px;color:var(--blue);font-weight:600;}
.topbar-time{font-family:var(--mono);font-size:11px;color:var(--text2);}

/* TABS */
.tab{display:none;padding:20px 24px;}
.tab.active{display:block;}

/* STATS */
.stats{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:20px;}
.card{
  background:var(--bg2);border:1px solid var(--border);
  border-radius:4px;padding:16px 14px;
  transition:border-color .15s;
}
.card:hover{border-color:var(--border2);}
.c-blue{border-top:2px solid var(--blue);}
.c-red{border-top:2px solid var(--red);}
.c-gray{border-top:2px solid var(--border2);}
.card-lbl{font-size:9px;letter-spacing:2px;color:var(--text2);margin-bottom:6px;text-transform:uppercase;}
.card-val{font-family:var(--mono);font-size:28px;font-weight:700;color:var(--text-bright);line-height:1;}
.card-title{font-size:9px;letter-spacing:1px;color:var(--text2);margin-top:6px;text-transform:uppercase;}

/* CHARTS */
.charts-row{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px;}
.chart-box,.section-box{
  background:var(--bg2);border:1px solid var(--border);
  border-radius:4px;padding:18px;margin-bottom:16px;
}
.chart-title{
  font-size:9px;letter-spacing:2.5px;color:var(--text2);
  text-transform:uppercase;margin-bottom:14px;
  padding-bottom:10px;border-bottom:1px solid var(--border);
}
.bar-chart{display:flex;flex-direction:column;gap:9px;}
.bar-row{display:flex;align-items:center;gap:10px;}
.bar-lbl{font-size:11px;width:100px;color:var(--text);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.bar-track{flex:1;background:var(--bg3);border-radius:1px;height:6px;overflow:hidden;}
.bar-fill{height:100%;background:var(--blue-dim);border-radius:1px;transition:width .5s ease;}
.bar-alt{background:#1a3355;}
.bar-red{background:var(--red-dim);}
.bar-num{font-family:var(--mono);font-size:11px;color:var(--text2);width:28px;text-align:right;}

/* TIMELINE */
.timeline{display:flex;flex-direction:column;gap:10px;}
.tl-item{display:flex;align-items:flex-start;gap:12px;padding:8px 0;border-bottom:1px solid var(--border);}
.tl-item:last-child{border-bottom:none;}
.tl-dot{width:8px;height:8px;border-radius:50%;margin-top:3px;flex-shrink:0;}
.dot-red{background:var(--red);}
.dot-yellow{background:#5a4a00;}
.dot-blue{background:var(--blue);}
.dot-gray{background:var(--border2);}
.tl-body{display:flex;gap:12px;flex-wrap:wrap;align-items:center;}
.tl-time{font-family:var(--mono);font-size:10px;color:var(--text2);min-width:130px;}
.tl-ip{font-family:var(--mono);font-size:11px;color:var(--blue);}
.tl-loc{font-size:11px;color:var(--text2);}
.tl-svc{font-size:11px;color:var(--text);}

/* TOOLBAR */
.toolbar{display:flex;gap:10px;margin-bottom:14px;}
.search-box{
  background:var(--bg2);border:1px solid var(--border);
  color:var(--text-bright);padding:9px 12px;border-radius:3px;
  font-family:var(--mono);font-size:12px;flex:1;outline:none;
  transition:border-color .15s;
}
.search-box:focus{border-color:var(--blue-dim);}
.sel{
  background:var(--bg2);border:1px solid var(--border);
  color:var(--text);padding:9px 12px;border-radius:3px;
  font-size:11px;outline:none;cursor:pointer;
}

/* TABLE */
.table-wrap{background:var(--bg2);border:1px solid var(--border);border-radius:4px;overflow:auto;max-height:580px;}
table{width:100%;border-collapse:collapse;}
thead{position:sticky;top:0;z-index:10;}
th{
  background:var(--bg3);padding:10px 12px;
  font-size:9px;font-weight:600;letter-spacing:2px;
  color:var(--text2);text-align:left;
  white-space:nowrap;border-bottom:1px solid var(--border);
  text-transform:uppercase;
}
td{padding:9px 12px;border-bottom:1px solid rgba(28,34,48,.8);vertical-align:middle;font-size:12px;}
tr:last-child td{border-bottom:none;}
tr:hover td{background:rgba(42,100,150,.04);}
.row-exploit td{background:rgba(139,32,32,.06);}
.row-scanner td{background:rgba(80,50,20,.05);}
.row-brute td{background:rgba(60,30,80,.05);}
.row-cred td{background:rgba(30,50,80,.05);}
tr.hidden{display:none;}

/* BADGES */
.badge{
  display:inline-block;padding:2px 7px;border-radius:2px;
  font-size:9px;font-weight:700;letter-spacing:1px;text-transform:uppercase;
}
.t-exploit{background:rgba(139,32,32,.3);color:#c05050;border:1px solid rgba(139,32,32,.4);}
.t-scanner{background:rgba(100,60,20,.3);color:#a07040;border:1px solid rgba(100,60,20,.4);}
.t-brute{background:rgba(80,40,100,.3);color:#9070b0;border:1px solid rgba(80,40,100,.4);}
.t-credencial{background:rgba(30,60,100,.3);color:#6090c0;border:1px solid rgba(30,60,100,.4);}
.t-normal{background:rgba(30,40,55,.3);color:var(--text2);border:1px solid var(--border);}

/* SERVICE BADGES */
.svc-badge{display:inline-block;padding:2px 7px;border-radius:2px;font-size:9px;font-weight:600;letter-spacing:1px;}
.svc-ssh{background:rgba(100,20,20,.2);color:#905050;border:1px solid rgba(100,20,20,.3);}
.svc-ftp{background:rgba(80,60,20,.2);color:#907050;border:1px solid rgba(80,60,20,.3);}
.svc-mysql{background:rgba(60,30,80,.2);color:#806090;border:1px solid rgba(60,30,80,.3);}
.svc-api{background:rgba(20,50,80,.2);color:#507090;border:1px solid rgba(20,50,80,.3);}
.svc-http{background:rgba(20,50,30,.2);color:#508060;border:1px solid rgba(20,50,30,.3);}
.svc-telnet{background:rgba(70,50,20,.2);color:#807050;border:1px solid rgba(70,50,20,.3);}
.svc-redis{background:rgba(80,20,20,.2);color:#905050;border:1px solid rgba(80,20,20,.3);}
.svc-elastic{background:rgba(20,60,80,.2);color:#508090;border:1px solid rgba(20,60,80,.3);}

/* MISC */
.mono{font-family:var(--mono);}
.dim{color:var(--text2);}
.ip{color:var(--blue);}
.center{text-align:center;}
.cred{color:#8b5050;font-family:var(--mono);font-weight:600;}
.empty{color:var(--text2);font-size:12px;padding:16px 0;}

/* MAP */
#map-container{display:flex;flex-direction:column;gap:16px;}
#map-svg-wrap{position:relative;background:var(--bg3);border:1px solid var(--border);border-radius:4px;overflow:hidden;}
#mapCanvas{position:absolute;top:0;left:0;width:100%;height:100%;}
#world-map{width:100%;height:auto;display:block;}
#map-legend{display:flex;gap:20px;padding:10px 0;}
.leg-item{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--text2);}
.leg-dot{width:8px;height:8px;border-radius:50%;}
.map-entries{display:flex;flex-direction:column;gap:8px;margin-top:12px;max-height:280px;overflow:auto;}
.map-entry{display:flex;justify-content:space-between;align-items:center;
  padding:10px 12px;background:var(--bg3);border:1px solid var(--border);border-radius:3px;}
.me-left{display:flex;flex-direction:column;gap:3px;}
.me-ip{font-size:12px;}
.me-loc{font-size:11px;color:var(--text);}
.me-org{font-size:10px;}
.me-right{display:flex;flex-direction:column;gap:6px;align-items:flex-end;}
.map-list{margin-top:16px;}
.map-link,.map-link-btn{
  color:var(--blue);text-decoration:none;font-size:11px;
  padding:3px 8px;border:1px solid var(--blue-dim);border-radius:2px;
  transition:background .15s;white-space:nowrap;
}
.map-link:hover,.map-link-btn:hover{background:rgba(42,100,150,.15);}

/* BLOCKED */
.blocked-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px;margin-top:10px;}
.blocked-item{
  background:var(--bg3);border:1px solid var(--border);
  border-radius:3px;padding:9px 12px;
  font-size:12px;
}

/* DIST */
.dist-list{display:flex;flex-direction:column;gap:11px;}
.dist-row{display:flex;align-items:center;gap:10px;}
.dist-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0;}
.dist-lbl{font-size:11px;width:75px;color:var(--text);}
.dist-pct{font-family:var(--mono);font-size:11px;color:var(--text2);width:34px;text-align:right;}

details summary{cursor:pointer;color:var(--text2);font-size:10px;letter-spacing:1px;user-select:none;}
details summary:hover{color:var(--text-bright);}
details pre{
  margin-top:8px;background:var(--bg);border:1px solid var(--border);
  border-radius:3px;padding:10px;font-size:10px;font-family:var(--mono);
  white-space:pre-wrap;word-break:break-all;
  max-width:360px;max-height:160px;overflow:auto;color:var(--text);
}

@media(max-width:1100px){.stats{grid-template-columns:repeat(3,1fr);}}
@media(max-width:800px){.stats{grid-template-columns:repeat(2,1fr);}.charts-row{grid-template-columns:1fr;}.sidebar{display:none;}.main{margin-left:0;}}
</style>
</head>
""";
    }

    static String htmlScripts(String mapaPoints) {
        return """
<script>
function showTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  event.target.classList.add('active');
  if (name === 'mapa') drawMap();
}

function filtrar() {
  const q    = document.getElementById('searchBox').value.toLowerCase();
  const tipo = document.getElementById('filterTipo').value;
  document.querySelectorAll('#tbl tbody tr').forEach(tr => {
    const txt  = tr.textContent.toLowerCase();
    const dt   = tr.dataset.tipo || '';
    const dc   = tr.dataset.cred || '';
    const mB   = txt.includes(q);
    const mT   = !tipo || tipo === dt || (tipo === 'CREDENCIAL' && dc === 'CREDENCIAL');
    tr.classList.toggle('hidden', !(mB && mT));
  });
}

const POINTS = [MAPA_POINTS_PLACEHOLDER];

function latLonToXY(lat, lon, w, h) {
  const x = (lon + 180) / 360 * w;
  const y = (90  - lat)  / 180 * h;
  return [x, y];
}

function drawMap() {
  const canvas = document.getElementById('mapCanvas');
  if (!canvas) return;
  const svg = document.getElementById('world-map');
  const W = svg.clientWidth  || 1000;
  const H = svg.clientHeight || 500;
  canvas.width  = W;
  canvas.height = H;
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, W, H);

  // Grid
  ctx.strokeStyle = 'rgba(28,34,48,0.8)';
  ctx.lineWidth = 0.5;
  for (let x = 0; x <= W; x += W/12) { ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x,H); ctx.stroke(); }
  for (let y = 0; y <= H; y += H/6)  { ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(W,y); ctx.stroke(); }

  POINTS.forEach(p => {
    const [x, y] = latLonToXY(parseFloat(p.lat), parseFloat(p.lon), W, H);
    ctx.beginPath();
    ctx.arc(x, y, 5, 0, Math.PI * 2);
    ctx.fillStyle = p.color + 'cc';
    ctx.fill();
    ctx.beginPath();
    ctx.arc(x, y, 9, 0, Math.PI * 2);
    ctx.strokeStyle = p.color + '55';
    ctx.lineWidth = 1;
    ctx.stroke();
  });

  canvas.onclick = function(e) {
    const rect = canvas.getBoundingClientRect();
    const mx = (e.clientX - rect.left) * (W / rect.width);
    const my = (e.clientY - rect.top)  * (H / rect.height);
    POINTS.forEach(p => {
      const [x, y] = latLonToXY(parseFloat(p.lat), parseFloat(p.lon), W, H);
      if (Math.hypot(mx - x, my - y) < 12) {
        alert(p.ip + ' — ' + p.city + ', ' + p.country + ' [' + p.tipo + '] ' + p.time);
      }
    });
  };
}

setTimeout(function(){
  if (!document.querySelector('details[open]')) location.reload();
}, 30000);
</script>
""".replace("MAPA_POINTS_PLACEHOLDER", mapaPoints);
    }

    // ========== BANNERS FALSOS ==========
    static String bannerFalso(int porta, String rota, String ip) {
        if (porta == 8080) {
            if (rota.startsWith("/api/v1/")) {
                String json = switch (rota) {
                    case "/api/v1/auth/login"      -> "{\"status\":\"error\",\"message\":\"Bad credentials\",\"attempts_remaining\":2}";
                    case "/api/v1/admin/dashboard" -> "{\"error\":\"Unauthorized\",\"code\":401}";
                    default                        -> "{\"message\":\"Not Found\",\"status\":404}";
                };
                int code = rota.contains("admin") ? 401 : rota.contains("login") ? 400 : 404;
                return "HTTP/1.1 " + code + " \r\nContent-Type: application/json\r\nServer: nginx/1.24.0\r\n\r\n" + json;
            }
            String html = loginPageHTML();
            return "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\n" +
                   "Content-Length: " + html.getBytes().length + "\r\n" +
                   "Server: Apache/2.4.57\r\nConnection: close\r\n\r\n" + html;
        }
        if (porta == 23)   return "\r\nUbuntu 22.04.3 LTS\r\nlogin: ";
        if (porta == 6379) return "-NOAUTH Authentication required.\r\n";
        if (porta == 9200) return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" +
            "{\"name\":\"node-1\",\"cluster_name\":\"production\",\"version\":{\"number\":\"8.11.0\"},\"tagline\":\"You Know, for Search\"}";
        String[] sshBanners = {
            "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
            "SSH-2.0-OpenSSH_7.4",
            "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11"
        };
        return switch (porta) {
            case 2222 -> sshBanners[Math.abs(ip.hashCode()) % sshBanners.length];
            case 2121 -> "220 ProFTPD 1.3.5 Server ready.";
            case 3307 -> "5.7.38-MySQL Community Server";
            default   -> "HTTP/1.1 200 OK\r\n\r\n<h1>OK</h1>";
        };
    }

    static String loginPageHTML() {
        return """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Authentication Required</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0;}
  body{
    font-family:'Segoe UI',Arial,sans-serif;
    min-height:100vh;display:flex;justify-content:center;align-items:center;
    background:url('data:image/jpeg;base64,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AAACAAoAAAAAAAAAAAAAIACgAAAAAAAAAAAgAKAAAAAAAAACAAoAAAIACgAAAAAgAAAKAAAAACAIkjwUSAAAAAAAAAAAAAgAKAAACAAAAoAIAAACgAAAgAKACAAAAAAoAAAIACgAAAgAAAKACAAoAIAAACgAAAAAgAAAKIk2SAAAAAAAAIACgAAAgAKAAAAAAAAACAAAAAAoAAAAAAAAAAAAAAAIACgAAAgAAAKAAAAAAAAACAAoAIACgAAACDckiASAAAAAAAAAAAgAKAAAAAAAAAAACAAoAIACgAACNgSAAAgAKAAACAAAAAAoAAAIAAACgI2SAAAAgAKAAAAAAAAAAAAAAAAIlIAAAAIACgAAjZIAAAAAAAAAAAAAAgAKAAAAACAAoAAAAAAAAAIAI2USAAAAAgAKAAAAIlIAAAAAAACISAAAAAAAAAAAAAAACJBIAAAAAAAAAAAAACN0o2BIAAAAAAAAAAAACAAAAoAAAAAAAAAIAAACgAAAAAAAAAAAgAAAAAKAAAhIACAAoI2SAjZIAAAAAAAI2SAAAAAAAAAAAAAAAAAiEgAAAAAACNkgAAAAACNwSAAAAAAjZIAAAAAACNkgAAAjZIAAghIKIhIAISAhKNjYEyjcnwASAAAAAAAgAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAoAAAAAAAAAAAAAAAAAIACgjdIAAgAKAAACAAoAAiSABIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIABIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI3BIAAAAAAAAAAAAAAAAAISgB/9k=') center/cover no-repeat;
    background-color:#06080b;
  }
  body::before{
    content:'';position:fixed;inset:0;
    background:rgba(4,6,10,.82);
    backdrop-filter:blur(2px);
  }
  .box{
    position:relative;z-index:1;
    background:rgba(10,13,18,.92);
    border:1px solid #1c2230;
    border-radius:4px;
    padding:36px 32px 32px;
    width:360px;
    box-shadow:0 20px 60px rgba(0,0,0,.8);
  }
  .logo-wrap{text-align:center;margin-bottom:24px;}
  .logo-wrap img{width:90px;height:auto;filter:brightness(.85);}
  .sys-label{
    text-align:center;font-size:9px;letter-spacing:3px;
    color:#3a4a60;margin-bottom:24px;text-transform:uppercase;
  }
  .divider{height:1px;background:#1c2230;margin-bottom:24px;}
  label{display:block;font-size:10px;letter-spacing:1.5px;color:#4a5a70;margin-bottom:6px;text-transform:uppercase;}
  input{
    width:100%;padding:10px 12px;
    background:rgba(14,18,24,.9);
    border:1px solid #1c2230;color:#8a9ab5;
    border-radius:3px;font-size:13px;
    font-family:'Courier New',Courier,monospace;
    margin-bottom:16px;outline:none;
    transition:border-color .15s;
  }
  input:focus{border-color:#2a6496;}
  .btn{
    width:100%;padding:11px;
    background:#0e1f30;border:1px solid #2a6496;
    color:#6090b0;font-size:11px;font-weight:600;
    letter-spacing:2px;border-radius:3px;cursor:pointer;
    text-transform:uppercase;transition:all .15s;
    font-family:'Segoe UI',Arial,sans-serif;
  }
  .btn:hover{background:#152a40;color:#8ab0d0;}
  .footer-txt{
    text-align:center;font-size:10px;
    color:#2a3a50;margin-top:20px;
    letter-spacing:1px;
  }
  .warn{
    font-size:9px;letter-spacing:1px;color:#3a2020;
    text-align:center;margin-top:12px;
    padding:6px;border:1px solid #2a1515;border-radius:2px;
  }
</style>
</head>
<body>
<div class="box">
  <div class="logo-wrap"><img src="data:image/jpeg;base64,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AAACAAoAAAAAAAAAAAAAIACgAAAAAAAAAAAgAKAAAAAAAAACAAoAAAIACgAAAAAgAAAKAAAAACAIkjwUSAAAAAAAAAAAAAgAKAAACAAAAoAIAAACgAAAgAKACAAAAAAoAAAIACgAAAgAAAKACAAoAIAAACgAAAAAgAAAKIk2SAAAAAAAAIACgAAAgAKAAAAAAAAACAAAAAAoAAAAAAAAAAAAAAAIACgAAAgAAAKAAAAAAAAACAAoAIACgAAACDckiASAAAAAAAAAAAgAKAAAAAAAAAAACAAoAIACgAACNgSAAAgAKAAACAAAAAAoAAAIAAACgI2SAAAAgAKAAAAAAAAAAAAAAAAIlIAAAAIACgAAjZIAAAAAAAAAAAAAAgAKAAAAACAAoAAAAAAAAAIAI2USAAAAAgAKAAAAIlIAAAAAAACISAAAAAAAAAAAAAAACJBIAAAAAAAAAAAAACN0o2BIAAAAAAAAAAAACAAAAoAAAAAAAAAIAAACgAAAAAAAAAAAgAAAAAKAAAhIACAAoI2SAjZIAAAAAAAI2SAAAAAAAAAAAAAAAAAiEgAAAAAACNkgAAAAACNwSAAAAAAjZIAAAAAACNkgAAAjZIAAghIKIhIAISAhKNjYEyjcnwASAAAAAAAgAKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAoAAAAAAAAAAAAAAAAAIACgjdIAAgAKAAACAAoAAiSABIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIABIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAI3BIAAAAAAAAAAAAAAAAAISgB/9k=" alt="Shutdown"/></div>
  <div class="sys-label">Secure System Access</div>
  <div class="divider"></div>
  <form action="/" method="POST" autocomplete="off">
    <label>Username</label>
    <input type="text" name="username" autocomplete="off" spellcheck="false" required>
    <label>Password</label>
    <input type="password" name="password" required>
    <button type="submit" class="btn">Authenticate</button>
  </form>
  <div class="footer-txt">SHUTDOWN SECURITY SYSTEMS</div>
  <div class="warn">⚠ Unauthorized access is strictly prohibited</div>
</div>
</body>
</html>
""";
    }

    // ========== LOG ==========
    static void salvaLogTXT(String ip, String horario, String servico,
            int porta, String usuario, String senha,
            String pais, String cidade, String org,
            String lat, String lon, String dados) {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(LOG_TXT, true))) {
            bw.write("=== CONEXAO ===\n");
            bw.write("Horario  : " + horario + "\n");
            bw.write("Servico  : " + servico + " (porta " + porta + ")\n");
            bw.write("IP       : " + ip + "\n");
            bw.write("Local    : " + cidade + " / " + pais + "\n");
            bw.write("Coords   : " + lat + ", " + lon + "\n");
            bw.write("Provedor : " + org + "\n");
            if (!usuario.isEmpty())
                bw.write("Credenc. : " + usuario + (senha.isEmpty() ? "" : " / " + senha) + "\n");
            bw.write("Dados    : " + (dados.isBlank() ? "(nenhum)" : dados.trim().substring(0, Math.min(500, dados.trim().length()))) + "\n\n");
        } catch (IOException ignored) {}
    }

    static void salvaEventoTXT(String ip, String evento) {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(LOG_TXT, true))) {
            bw.write("=== EVENTO ===\n");
            bw.write("Horario : " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss")) + "\n");
            bw.write("IP      : " + ip + "\n");
            bw.write("Evento  : " + evento + "\n\n");
        } catch (IOException ignored) {}
    }

    static void salvaAmeaca(String ip, String horario, String descricao) {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(LOG_THREATS, true))) {
            bw.write("=== AMEACA ===\n");
            bw.write("Horario : " + horario + "\n");
            bw.write("IP      : " + ip + "\n");
            bw.write("Descr.  : " + descricao + "\n\n");
        } catch (IOException ignored) {}
    }

    // ========== HELPERS ==========
    static String[] extraiCredenciais(String dados) {
        String u = "", s = "";
        for (String linha : dados.split("\n")) {
            String l = linha.toLowerCase().trim();
            if (l.startsWith("user ") || l.startsWith("login:"))
                u = sanitiza(linha.replaceAll("(?i)(user |login:)", "").trim(), 100);
            if (l.startsWith("pass ") || l.startsWith("password:"))
                s = sanitiza(linha.replaceAll("(?i)(pass |password:)", "").trim(), 100);
            if (l.startsWith("authorization: basic ")) {
                try {
                    String dec = new String(Base64.getDecoder().decode(linha.split(" ")[2]));
                    String[] p = dec.split(":", 2);
                    if (p.length == 2) { u = sanitiza(p[0], 100); s = sanitiza(p[1], 100); }
                } catch (Exception ignored) {}
            }
        }
        return new String[]{u, s};
    }

    static String nomeServico(int porta) {
        return switch (porta) {
            case 8080 -> "HTTP";
            case 2222 -> "SSH";
            case 2121 -> "FTP";
            case 3307 -> "MySQL";
            case 23   -> "Telnet";
            case 6379 -> "Redis";
            case 9200 -> "Elasticsearch";
            default   -> "Unknown";
        };
    }

    static void silentClose(Socket s) {
        try { if (s != null) s.close(); } catch (Exception ignored) {}
    }
}