import java.util.*;
import java.util.regex.*;
import java.util.stream.Collectors;

public class Main {

    // modelagem do log
    public record LogEvent(String timestamp, String host, String action, String srcIp, String destIp, int bytes, String user) {}

    // extracao de campos do log
    private static LogEvent parseLine(String line) {
        String timestamp = extractValue(line, "time=([^\\s]+)");
        String host = extractValue(line, "host=([^\\s]+)");
        String action = extractValue(line, "action=([^\\s]+)");
        String srcIp = extractValue(line, "src_ip=([^\\s]+)");
        String destIp = extractValue(line, "dest_ip=([^\\s]+)");
        String bytesStr = extractValue(line, "bytes=([^\\s]+)");
        String user = extractValue(line, "user=([^\\s]+)");

        int bytes = bytesStr != null ? Integer.parseInt(bytesStr) : 0;

        return new LogEvent(timestamp, host, action, srcIp, destIp, bytes, user);
    }

    private static String extractValue(String line, String regex) {
        Matcher matcher = Pattern.compile(regex).matcher(line);
        return matcher.find() ? matcher.group(1) : null;
    }

    // regras de classificacao SOC n1 e n2
    private static String classificarAmeaca(LogEvent log) {
        if ("Proxy-Edge-01".equals(log.host()) && log.bytes() == 2450 && "10.0.0.1".equals(log.destIp())) {
            return "CRÍTICO - N2: Possível Malware Beaconing / C2 (Tráfego padronizado)";
        }

        if ("srv-linux-01".equals(log.host()) && "root".equals(log.user()) && "accepted".equals(log.action())) {
            return "ALTO - N2: Login de Root aceito fora do padrão";
        }

        return "INFO - N1: Tráfego Normal";
    }

    public static void main(String[] args) {
        // amostra de logs para demonstracao mais limpa e clara no terminal
        List<String> linhasDeLogRaw = Arrays.asList(
                "time=10:00:01 host=Proxy-Edge-01 action=allow src_ip=10.0.0.24 dest_ip=10.0.0.1 bytes=2450",
                "time=10:00:02 host=srv-linux-01 action=accepted src_ip=10.0.0.48 dest_ip=10.0.1.5 bytes=120 user=root",
                "time=10:00:03 host=SRV-WEB-01 action=success src_ip=10.0.0.15 dest_ip=10.0.1.10 bytes=500 user=c_santos",
                "time=10:00:04 host=Proxy-Edge-01 action=allow src_ip=10.0.0.83 dest_ip=10.0.0.1 bytes=2450"
        );
        //inicialiazacao de analise dos logs do ficheiro dataset_lab.log
        System.out.println("=== INICIANDO ANÁLISE DE LOGS ===\n");

        List<LogEvent> eventosProcessados = linhasDeLogRaw.stream()
                .map(Main::parseLine)
                .collect(Collectors.toList());

        // processsamento n1/n2
        for (LogEvent evento : eventosProcessados) {
            String classificacao = classificarAmeaca(evento);
            System.out.printf("[%s] Host: %s | Origem: %s -> Destino: %s | Classificação: %s%n",
                    evento.timestamp(), evento.host(), evento.srcIp(), evento.destIp(), classificacao);
        }

        System.out.println("\n=== CORRELAÇÃO DE DADOS (N3) ===");

        // modulo de correlacao n3
        Map<String, Long> acessosPorDestino = eventosProcessados.stream()
                .collect(Collectors.groupingBy(LogEvent::destIp, Collectors.counting()));

        acessosPorDestino.forEach((ip, contagem) -> {
            if (contagem > 1) {
                System.out.println("ALERTA DE CORRELAÇÃO: O IP destino " + ip + " recebeu " + contagem + " conexões em curto período!");
            }
        });
    }
}
