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

    static final String LOG_TXT  = "honeypot_log.txt";
    static final String LOG_HTML = "honeypot_report.html";
    static final int[]  PORTAS   = { 8080, 2222, 2121, 3307 };
    static final int    MAX_BODY = 8192;       // 8KB máximo por body
    static final int    MAX_CONN = 50;         // máximo de threads simultâneas
    static final int    MAX_LOG  = 1000;       // máximo de entradas na lista
    static final int    RATE_LIM = 15;         // máximo de conexões por IP

    // ========== ESTADO GLOBAL ==========
    static final List<String[]>        conexoes   = Collections.synchronizedList(new ArrayList<>());
    static final Map<String,Integer>   contadorIP = new ConcurrentHashMap<>();
    static final Set<String>           bloqueados = ConcurrentHashMap.newKeySet();
    static final AtomicLong            totalConn  = new AtomicLong(0);
    static final AtomicLong            totalBloq  = new AtomicLong(0);
    static final ExecutorService       pool       = Executors.newFixedThreadPool(MAX_CONN);
    static final Map<String,Long>      ultimaConn = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        printBanner();

        // Inicia servidores em cada porta
        for (int porta : PORTAS) {
            final int p = porta;
            new Thread(() -> iniciaServidor(p), "srv-" + p).start();
        }

        // Relatório HTML a cada 30s
        Executors.newSingleThreadScheduledExecutor().scheduleAtFixedRate(
            Honeypot::geraRelatorioHTML, 10, 30, TimeUnit.SECONDS);

        // Stats no terminal a cada 60s
        Executors.newSingleThreadScheduledExecutor().scheduleAtFixedRate(
            Honeypot::printStats, 60, 60, TimeUnit.SECONDS);

        try { Thread.currentThread().join(); }
        catch (InterruptedException e) { Thread.currentThread().interrupt(); }
    }

    // ========== BANNER TERMINAL ==========
    static void printBanner() {
        System.out.println(NEG + CIANO);
        System.out.println("  ╔══════════════════════════════════════════════╗");
        System.out.println("  ║                                              ║");
        System.out.println("  ║   ██╗  ██╗ ██████╗ ███╗  ██╗███████╗██╗   ║");
        System.out.println("  ║   ██║  ██║██╔═══██╗████╗ ██║██╔════╝╚██╗  ║");
        System.out.println("  ║   ███████║██║   ██║██╔██╗██║█████╗   ╚██╗ ║");
        System.out.println("  ║   ██╔══██║██║   ██║██║╚████║██╔══╝   ██╔╝ ║");
        System.out.println("  ║   ██║  ██║╚██████╔╝██║ ╚███║███████╗██╔╝  ║");
        System.out.println("  ║   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚══╝╚══════╝╚═╝  ║");
        System.out.println("  ║                                              ║");
        System.out.println("  ║        HONEYPOT  —  SHUTDOWN SEC            ║");
        System.out.println("  ║                                              ║");
        System.out.println("  ╚══════════════════════════════════════════════╝" + RESET);
        System.out.println();
    }

    static void printStats() {
        System.out.println(DIM + CIANO +
            "\n  ┌─ STATS ──────────────────────────────────┐" +
            "\n  │  Conexões totais : " + totalConn.get() +
            "\n  │  IPs bloqueados  : " + bloqueados.size() +
            "\n  │  Entradas no log : " + conexoes.size() +
            "\n  └──────────────────────────────────────────┘" + RESET);
    }

    // ========== SERVIDOR POR PORTA ==========
    static void iniciaServidor(int porta) {
        System.out.println(VERDE + "  [+] " + RESET +
            "Escutando " + NEG + nomeServico(porta) + RESET +
            " na porta " + AMAR + porta + RESET);
        try (ServerSocket srv = new ServerSocket(porta)) {
            srv.setReuseAddress(true);
            while (true) {
                try {
                    Socket cliente = srv.accept();
                    cliente.setSoTimeout(3000);
                    pool.submit(() -> trataConexao(cliente, porta));
                } catch (IOException e) {
                    // Aceita próxima conexão
                }
            }
        } catch (IOException e) {
            System.out.println(VERM + "  [!] Erro porta " + porta +
                ": " + e.getMessage() + RESET);
        }
    }

    // ========== TRATA CONEXÃO ==========
    static void trataConexao(Socket cliente, int porta) {
        String ip = cliente.getInetAddress().getHostAddress();

        // ── Proteção 1: IP bloqueado ──────────────────────
        if (bloqueados.contains(ip)) {
            totalBloq.incrementAndGet();
            silentClose(cliente);
            return;
        }

        // ── Proteção 2: Rate limiting por IP ─────────────
        int tentativas = contadorIP.merge(ip, 1, Integer::sum);
        if (tentativas > RATE_LIM) {
            bloqueados.add(ip);
            totalBloq.incrementAndGet();
            System.out.println(VERM + NEG + "  [BLOQUEADO] " + RESET +
                VERM + ip + " (" + tentativas + " tentativas)" + RESET);
            salvaEventoTXT(ip, "IP BLOQUEADO por rate limit (" + tentativas + " tentativas)");
            silentClose(cliente);
            return;
        }

        // ── Proteção 3: Cooldown por IP (500ms mínimo) ───
        long agora = System.currentTimeMillis();
        Long ultima = ultimaConn.put(ip, agora);
        if (ultima != null && (agora - ultima) < 500) {
            silentClose(cliente);
            return;
        }

        totalConn.incrementAndGet();
        String horario = LocalDateTime.now()
            .format(DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss"));
        String servico = nomeServico(porta);

        try (
            BufferedReader entrada = new BufferedReader(
                new InputStreamReader(cliente.getInputStream()));
            PrintWriter saida = new PrintWriter(cliente.getOutputStream(), true)
        ) {
            StringBuilder cabecalhos = new StringBuilder();
            String metodo = "UNKNOWN", rota = "/";
            int contentLength = 0;

            // Lê cabeçalhos
            try {
                boolean primeira = true;
                String linha;
                while ((linha = entrada.readLine()) != null && !linha.isEmpty()) {
                    cabecalhos.append(linha).append("\n");
                    if (primeira) {
                        String[] p = linha.split(" ");
                        if (p.length >= 2) { metodo = p[0]; rota = p[1]; }
                        primeira = false;
                    }
                    if (linha.toLowerCase().startsWith("content-length:")) {
                        try {
                            contentLength = Integer.parseInt(linha.substring(15).trim());
                        } catch (NumberFormatException ignored) {}
                    }
                }
            } catch (IOException ignored) {}

            // ── Proteção 4: Limite de tamanho do body ────
            StringBuilder body = new StringBuilder();
            int limite = Math.min(contentLength, MAX_BODY);
            if (limite > 0) {
                try {
                    char[] buf = new char[limite];
                    int lido = entrada.read(buf, 0, limite);
                    if (lido > 0) body.append(buf, 0, lido);
                } catch (IOException ignored) {}
            }

            String bodyStr = body.toString();
            String dadosFull = cabecalhos + "\n" + bodyStr;

            // Envia banner falso
            try {
                saida.print(bannerFalso(porta, rota));
                saida.flush();
            } catch (Exception ignored) {}

            // Extrai credenciais
            String usuario = "", senha = "";
            if (rota.startsWith("/api/v1/") && bodyStr.contains("{")) {
                servico = "API (" + metodo + ")";
                usuario = "[JSON]";
                senha = bodyStr.trim();
            } else if (bodyStr.contains("username=") && bodyStr.contains("password=")) {
                for (String param : bodyStr.split("&")) {
                    try {
                        if (param.startsWith("username="))
                            usuario = java.net.URLDecoder.decode(
                                param.substring(9), "UTF-8");
                        if (param.startsWith("password="))
                            senha = java.net.URLDecoder.decode(
                                param.substring(9), "UTF-8");
                    } catch (Exception ignored) {}
                }
            } else {
                String[] cred = extraiCredenciais(dadosFull);
                usuario = cred[0]; senha = cred[1];
            }

            // ── Proteção 5: Detecta scanners conhecidos ──
            String ua = "";
            for (String h : cabecalhos.toString().split("\n")) {
                if (h.toLowerCase().startsWith("user-agent:")) {
                    ua = h.substring(11).trim().toLowerCase();
                    break;
                }
            }
            boolean scanner = ua.contains("nmap") || ua.contains("masscan") ||
                              ua.contains("zgrab") || ua.contains("nikto") ||
                              ua.contains("sqlmap") || ua.contains("shodan");

            // Ignora pings vazios na raiz
            boolean relevante = !bodyStr.isEmpty() || !usuario.isEmpty() ||
                                 porta != 8080 || !rota.equals("/") || scanner;

            if (!relevante) { silentClose(cliente); return; }

            // Geolocalização em background (não bloqueia a thread principal)
            String[] geo = geolocalizaIP(ip);
            String pais = geo[0], cidade = geo[1], org = geo[2];

            // Exibe no terminal
            String tipoAlerta = scanner ? VERM + NEG + "🔍 SCANNER DETECTADO" :
                               (!usuario.isEmpty() ? VERM + NEG + "🔑 CREDENCIAL CAPTURADA" :
                               AMAR + NEG + "⚠  CONEXÃO");
            System.out.println(tipoAlerta + RESET);
            System.out.println(DIM + "  ┌─────────────────────────────────────" + RESET);
            System.out.println("  │ " + AMAR + "Serviço  " + RESET + servico +
                (porta != 8080 ? "" : " → " + rota));
            System.out.println("  │ " + AMAR + "IP       " + RESET + ip +
                (scanner ? VERM + " [SCANNER]" + RESET : ""));
            System.out.println("  │ " + AMAR + "Local    " + RESET + cidade + " / " + pais);
            System.out.println("  │ " + AMAR + "Provedor " + RESET + org);
            System.out.println("  │ " + AMAR + "Horário  " + RESET + horario);
            System.out.println("  │ " + AMAR + "Tentativ " + RESET + tentativas + "x deste IP");
            if (!usuario.isEmpty())
                System.out.println("  │ " + VERM + NEG + "Login    " + RESET +
                    VERM + usuario + (senha.isEmpty() ? "" : " / " + senha) + RESET);
            System.out.println(DIM + "  └─────────────────────────────────────" + RESET);

            // ── Proteção 6: Limite da lista em memória ───
            synchronized (conexoes) {
                if (conexoes.size() >= MAX_LOG) conexoes.remove(0);
                conexoes.add(new String[]{
                    horario, ip, pais, cidade, org, servico, rota,
                    usuario, senha,
                    bodyStr.isEmpty() ? "(sem payload)" : bodyStr,
                    scanner ? "SCANNER" : "NORMAL",
                    String.valueOf(tentativas)
                });
            }

            salvaLogTXT(ip, horario, servico, porta, usuario, senha,
                pais, cidade, org, dadosFull);
            geraRelatorioHTML();

        } catch (Exception e) {
            // Erros silenciosos para manter terminal limpo
        } finally {
            silentClose(cliente);
        }
    }

    // ========== GEOLOCALIZAÇÃO ==========
    static String[] geolocalizaIP(String ip) {
        if (ip.startsWith("127.") || ip.startsWith("192.168.") ||
            ip.startsWith("10.")  || ip.contains(":")) {
            return new String[]{"Brasil", "Localhost", "Rede Local"};
        }
        try {
            HttpClient hc = HttpClient.newBuilder()
                .connectTimeout(java.time.Duration.ofSeconds(3))
                .build();
            HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create("http://ip-api.com/json/" + ip +
                    "?fields=country,city,org"))
                .timeout(java.time.Duration.ofSeconds(3))
                .build();
            HttpResponse<String> resp =
                hc.send(req, HttpResponse.BodyHandlers.ofString());
            String b = resp.body();
            String pais   = extraiJson(b, "country");
            String cidade = extraiJson(b, "city");
            String org    = extraiJson(b, "org");
            return new String[]{
                pais.isEmpty()   ? "?" : pais,
                cidade.isEmpty() ? "?" : cidade,
                org.isEmpty()    ? "?" : org
            };
        } catch (Exception e) {
            return new String[]{"?", "?", "?"};
        }
    }

    static String extraiJson(String json, String campo) {
        String chave = "\"" + campo + "\":\"";
        int i = json.indexOf(chave);
        if (i < 0) return "";
        i += chave.length();
        int f = json.indexOf("\"", i);
        return f < 0 ? "" : json.substring(i, f);
    }

    // ========== RELATÓRIO HTML ==========
    static void geraRelatorioHTML() {
        try (PrintWriter pw = new PrintWriter(new FileWriter(LOG_HTML))) {
            pw.print(htmlHead());
            pw.println("<body>");
            pw.println("<div class='scanline'></div>");
            pw.println("<div class='container'>");

            // Header
            pw.println("<header>");
            pw.println("<div class='logo'><span class='bracket'>[</span>SHUTDOWN<span class='bracket'>]</span> <span class='sub'>HONEYPOT INTELLIGENCE</span></div>");
            pw.println("<div class='meta'>Atualizado: " +
                LocalDateTime.now().format(
                    DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss")) +
                "</div>");
            pw.println("</header>");

            // Cards de stats
            long scanners = conexoes.stream()
                .filter(c -> "SCANNER".equals(c[10])).count();
            long comCred = conexoes.stream()
                .filter(c -> !c[7].isEmpty()).count();

            pw.println("<div class='stats'>");
            pw.println(card("CONEXÕES", String.valueOf(conexoes.size()), "stat-blue"));
            pw.println(card("BLOQUEADOS", String.valueOf(bloqueados.size()), "stat-red"));
            pw.println(card("SCANNERS", String.valueOf(scanners), "stat-orange"));
            pw.println(card("CREDENCIAIS", String.valueOf(comCred), "stat-green"));
            pw.println("</div>");

            // Tabela
            pw.println("<div class='table-wrap'>");
            pw.println("<table>");
            pw.println("<thead><tr>" +
                "<th>HORÁRIO</th><th>IP</th><th>PAÍS</th><th>CIDADE</th>" +
                "<th>PROVEDOR</th><th>SERVIÇO</th><th>ROTA</th>" +
                "<th>CREDENCIAIS</th><th>TENTATIVAS</th><th>PAYLOAD</th>" +
                "</tr></thead><tbody>");

            synchronized (conexoes) {
                // Mais recentes primeiro
                List<String[]> copia = new ArrayList<>(conexoes);
                Collections.reverse(copia);
                for (String[] c : copia) {
                    boolean isScanner = "SCANNER".equals(c[10]);
                    boolean temCred   = !c[7].isEmpty();
                    String rowClass   = isScanner ? "row-scanner" :
                                        temCred   ? "row-cred" : "";
                    String credHtml   = temCred ?
                        "<span class='cred'>" + esc(c[7]) +
                        (c[8].isEmpty() ? "" : " / " + esc(c[8])) +
                        "</span>" : "<span class='dim'>—</span>";
                    String badgeServico = "<span class='badge badge-" +
                        badgeClass(c[5]) + "'>" + esc(c[5]) + "</span>";

                    pw.println("<tr class='" + rowClass + "'>" +
                        "<td class='mono'>" + c[0] + "</td>" +
                        "<td class='mono ip'>" + c[1] + "</td>" +
                        "<td>" + c[2] + "</td>" +
                        "<td>" + c[3] + "</td>" +
                        "<td class='dim'>" + esc(c[4]) + "</td>" +
                        "<td>" + badgeServico + "</td>" +
                        "<td class='mono dim'>" + esc(c[6]) + "</td>" +
                        "<td>" + credHtml + "</td>" +
                        "<td class='center'><span class='attempts'>" + c[11] + "x</span></td>" +
                        "<td><details><summary>ver</summary><pre>" +
                        esc(c[9]) + "</pre></details></td>" +
                        "</tr>");
                }
            }

            pw.println("</tbody></table></div>");
            pw.println("</div></body></html>");

        } catch (IOException e) {
            System.out.println(VERM + "  [!] Erro HTML: " + e.getMessage() + RESET);
        }
    }

    static String card(String titulo, String valor, String cls) {
        return "<div class='card " + cls + "'>" +
               "<div class='card-val'>" + valor + "</div>" +
               "<div class='card-lbl'>" + titulo + "</div>" +
               "</div>";
    }

    static String badgeClass(String servico) {
        String s = servico.toLowerCase();
        if (s.contains("ssh"))   return "ssh";
        if (s.contains("ftp"))   return "ftp";
        if (s.contains("mysql")) return "mysql";
        if (s.contains("api"))   return "api";
        return "http";
    }

    static String esc(String s) {
        if (s == null) return "";
        return s.replace("&","&amp;").replace("<","&lt;")
                .replace(">","&gt;").replace("\"","&quot;");
    }

    // CSS / HTML do relatório
    static String htmlHead() {
        return """
            <!DOCTYPE html>
            <html lang="pt-br">
            <head>
            <meta charset="UTF-8">
            <meta http-equiv="refresh" content="30">
            <title>Honeypot — Shutdown Intelligence</title>
            <style>
              @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

              :root {
                --bg:       #050508;
                --bg2:      #0a0a10;
                --bg3:      #0f0f18;
                --border:   #1a1a2e;
                --cyan:     #00e5ff;
                --green:    #00ff88;
                --red:      #ff2d55;
                --orange:   #ff9500;
                --yellow:   #ffd60a;
                --dim:      #3a3a5c;
                --text:     #c8c8e8;
                --mono:     'Share Tech Mono', monospace;
                --sans:     'Rajdhani', sans-serif;
              }

              * { box-sizing: border-box; margin: 0; padding: 0; }

              body {
                background: var(--bg);
                color: var(--text);
                font-family: var(--sans);
                min-height: 100vh;
                overflow-x: hidden;
              }

              /* scanline overlay */
              .scanline {
                position: fixed; inset: 0; z-index: 999; pointer-events: none;
                background: repeating-linear-gradient(
                  0deg,
                  transparent,
                  transparent 2px,
                  rgba(0,229,255,.015) 2px,
                  rgba(0,229,255,.015) 4px
                );
              }

              .container { max-width: 1400px; margin: 0 auto; padding: 24px; }

              /* Header */
              header {
                display: flex; justify-content: space-between; align-items: center;
                padding: 20px 0 24px;
                border-bottom: 1px solid var(--border);
                margin-bottom: 28px;
              }
              .logo {
                font-family: var(--sans);
                font-size: 22px; font-weight: 700;
                letter-spacing: 4px; color: #fff;
              }
              .logo .bracket { color: var(--cyan); }
              .logo .sub {
                font-size: 11px; font-weight: 400;
                letter-spacing: 6px; color: var(--dim);
                display: block; margin-top: 2px;
              }
              .meta { font-family: var(--mono); font-size: 12px; color: var(--dim); }

              /* Stats cards */
              .stats {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 16px; margin-bottom: 28px;
              }
              .card {
                background: var(--bg2);
                border: 1px solid var(--border);
                border-radius: 6px;
                padding: 20px 24px;
                position: relative; overflow: hidden;
                transition: border-color .2s;
              }
              .card::before {
                content: ''; position: absolute;
                top: 0; left: 0; right: 0; height: 2px;
              }
              .stat-blue::before  { background: var(--cyan); }
              .stat-red::before   { background: var(--red); }
              .stat-orange::before{ background: var(--orange); }
              .stat-green::before { background: var(--green); }
              .card:hover { border-color: var(--cyan); }
              .card-val {
                font-family: var(--mono); font-size: 36px;
                font-weight: 700; line-height: 1;
              }
              .stat-blue  .card-val { color: var(--cyan); }
              .stat-red   .card-val { color: var(--red); }
              .stat-orange.card-val,
              .stat-orange .card-val { color: var(--orange); }
              .stat-green .card-val { color: var(--green); }
              .card-lbl {
                font-size: 11px; letter-spacing: 3px;
                color: var(--dim); margin-top: 8px;
              }

              /* Table */
              .table-wrap {
                background: var(--bg2);
                border: 1px solid var(--border);
                border-radius: 6px;
                overflow: auto;
              }
              table { width: 100%; border-collapse: collapse; }
              thead { position: sticky; top: 0; z-index: 10; }
              th {
                background: var(--bg3);
                padding: 12px 14px;
                font-family: var(--sans);
                font-size: 10px; font-weight: 700;
                letter-spacing: 2px; color: var(--cyan);
                text-align: left; white-space: nowrap;
                border-bottom: 1px solid var(--border);
              }
              td {
                padding: 10px 14px;
                font-size: 13px;
                border-bottom: 1px solid rgba(26,26,46,.6);
                vertical-align: top;
              }
              tr:last-child td { border-bottom: none; }
              tr:hover td { background: rgba(0,229,255,.03); }

              .row-scanner td { background: rgba(255,45,85,.04); }
              .row-cred    td { background: rgba(255,149,0,.04); }

              .mono { font-family: var(--mono); font-size: 12px; }
              .dim  { color: var(--dim); }
              .ip   { color: var(--cyan); }
              .center { text-align: center; }

              /* Badges */
              .badge {
                display: inline-block;
                padding: 2px 8px; border-radius: 3px;
                font-size: 10px; font-weight: 700;
                letter-spacing: 1px;
              }
              .badge-ssh   { background: rgba(255,45,85,.2);   color: var(--red);    border: 1px solid rgba(255,45,85,.3); }
              .badge-ftp   { background: rgba(255,214,10,.15); color: var(--yellow); border: 1px solid rgba(255,214,10,.3); }
              .badge-mysql { background: rgba(175,82,222,.2);  color: #bf5af2;       border: 1px solid rgba(175,82,222,.3);}
              .badge-api   { background: rgba(0,229,255,.15);  color: var(--cyan);   border: 1px solid rgba(0,229,255,.3); }
              .badge-http  { background: rgba(0,255,136,.12);  color: var(--green);  border: 1px solid rgba(0,255,136,.25);}

              .cred { color: var(--red); font-family: var(--mono); font-size: 12px; font-weight: 600; }
              .attempts { color: var(--orange); font-family: var(--mono); font-size: 12px; }

              /* Payload expandível */
              details summary {
                cursor: pointer; color: var(--dim);
                font-size: 11px; letter-spacing: 1px;
                user-select: none;
              }
              details summary:hover { color: var(--cyan); }
              details pre {
                margin-top: 8px;
                background: var(--bg);
                border: 1px solid var(--border);
                border-radius: 4px;
                padding: 10px; font-size: 11px;
                font-family: var(--mono);
                white-space: pre-wrap; word-break: break-all;
                max-width: 400px; max-height: 200px;
                overflow: auto; color: var(--text);
              }

              @media (max-width: 768px) {
                .stats { grid-template-columns: repeat(2,1fr); }
              }
            </style>
            </head>
            """;
    }

    // ========== LOG TXT ==========
    static void salvaLogTXT(String ip, String horario, String servico,
            int porta, String usuario, String senha,
            String pais, String cidade, String org, String dados) {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(LOG_TXT, true))) {
            bw.write("=== CONEXÃO ===\n");
            bw.write("Horário  : " + horario + "\n");
            bw.write("Serviço  : " + servico + " (porta " + porta + ")\n");
            bw.write("IP       : " + ip + "\n");
            bw.write("Local    : " + cidade + " / " + pais + "\n");
            bw.write("Provedor : " + org + "\n");
            if (!usuario.isEmpty())
                bw.write("Credenc. : " + usuario +
                    (senha.isEmpty() ? "" : " / " + senha) + "\n");
            bw.write("Dados    : " +
                (dados.isBlank() ? "(nenhum)" : dados.trim()) + "\n\n");
        } catch (IOException e) {
            System.out.println(VERM + "  [!] Erro log: " + e.getMessage() + RESET);
        }
    }

    static void salvaEventoTXT(String ip, String evento) {
        try (BufferedWriter bw = new BufferedWriter(new FileWriter(LOG_TXT, true))) {
            bw.write("=== EVENTO ===\n");
            bw.write("IP     : " + ip + "\n");
            bw.write("Evento : " + evento + "\n\n");
        } catch (IOException ignored) {}
    }

    // ========== HELPERS ==========
    static String[] extraiCredenciais(String dados) {
        String u = "", s = "";
        for (String linha : dados.split("\n")) {
            String l = linha.toLowerCase().trim();
            if (l.startsWith("user ") || l.startsWith("login:"))
                u = linha.replaceAll("(?i)(user |login:)", "").trim();
            if (l.startsWith("pass ") || l.startsWith("password:"))
                s = linha.replaceAll("(?i)(pass |password:)", "").trim();
            if (l.startsWith("authorization: basic ")) {
                try {
                    String dec = new String(Base64.getDecoder()
                        .decode(linha.split(" ")[2]));
                    String[] p = dec.split(":", 2);
                    if (p.length == 2) { u = p[0]; s = p[1]; }
                } catch (Exception ignored) {}
            }
        }
        return new String[]{u, s};
    }

    static String bannerFalso(int porta, String rota) {
        if (porta == 8080) {
            if (rota.startsWith("/api/v1/")) {
                String json = switch (rota) {
                    case "/api/v1/auth/login" ->
                        "{\"status\":\"error\",\"message\":\"Bad credentials\",\"attempts_remaining\":2}";
                    case "/api/v1/admin/dashboard" ->
                        "{\"error\":\"Unauthorized\",\"code\":401}";
                    default -> "{\"message\":\"Not Found\",\"status\":404}";
                };
                int code = rota.contains("admin") ? 401 :
                           rota.contains("login") ? 400 : 404;
                return "HTTP/1.1 " + code + " \r\n" +
                       "Content-Type: application/json\r\n" +
                       "Server: nginx/1.24.0\r\n\r\n" + json;
            }
            String html = loginPageHTML();
            return "HTTP/1.1 200 OK\r\n" +
                   "Content-Type: text/html; charset=UTF-8\r\n" +
                   "Content-Length: " + html.getBytes().length + "\r\n" +
                   "Server: Apache/2.4.57\r\nConnection: close\r\n\r\n" + html;
        }
        return switch (porta) {
            case 2222 -> "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6";
            case 2121 -> "220 ProFTPD 1.3.5 Server (ProFTPD) ready.";
            case 3307 -> "5.7.38-MySQL Community Server";
            default   -> "HTTP/1.1 200 OK\r\n\r\n<h1>OK</h1>";
        };
    }

    static String loginPageHTML() {
        return """
            <!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
            <title>Admin Panel — Secure Login</title>
            <style>
              body{background:#111;color:#eee;font-family:sans-serif;
                   display:flex;justify-content:center;align-items:center;
                   height:100vh;margin:0;}
              .box{background:#1a1a1a;padding:36px;border-radius:8px;
                   box-shadow:0 8px 32px #000;width:340px;}
              h2{color:#007bff;text-align:center;margin-bottom:24px;
                 font-size:18px;letter-spacing:2px;}
              label{font-size:12px;color:#888;display:block;margin-bottom:6px;}
              input{width:100%;padding:10px;background:#252525;border:1px solid #333;
                    color:#fff;border-radius:4px;margin-bottom:16px;
                    box-sizing:border-box;font-size:14px;}
              button{width:100%;padding:11px;background:#007bff;border:none;
                     color:#fff;font-size:15px;border-radius:4px;cursor:pointer;}
              button:hover{background:#0056b3;}
              .hint{text-align:center;font-size:11px;color:#444;margin-top:14px;}
            </style></head><body>
            <div class="box">
              <h2>SYSTEM LOGIN</h2>
              <form action="/" method="POST">
                <label>USERNAME</label>
                <input type="text" name="username" autocomplete="off" required>
                <label>PASSWORD</label>
                <input type="password" name="password" required>
                <button>AUTHENTICATE</button>
              </form>
              <p class="hint">Unauthorized access is prohibited</p>
            </div></body></html>
            """;
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

    static void silentClose(Socket s) {
        try { if (s != null) s.close(); } catch (Exception ignored) {}
    }
}