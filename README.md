# Sistema de Analise de Logs e Deteccao de Ameasas SOC (Java)

## Sobre o Projeto

Este projeto simula um pipeline de analise de logs de um Centro de Operacoes de Seguranca (SOC) construido em Java. Ele realiza o processamento (parsing) de dados brutos de logs, categoriza potenciais ameacas de seguranca em niveis operacionais de resposta (N1, N2 e N3) e detecta comportamentos anomalos de rede, como comunicacao de malware Command & Control (C2) / Beaconing e acessos privilegiados nao autorizados.

## Arquitetura e Modelo de Niveis SOC

O motor de deteccao categoriza os eventos atraves de uma estrutura de analise de ameacas em tres camadas:

| Nivel SOC | Funcao | Detalhes de Implementacao | 
| ----- | ----- | ----- | 
| Nivel 1 (N1) | Triagem e Leitura | Extrai campos de logs em formato texto usando padroes Regex e classifica atividades normais de rotina (INFO). | 
| Nivel 2 (N2) | Identificacao de Ameacas | Detecta anomalias de alta prioridade, incluindo logins SSH de root nao autorizados (ALTO) e padroes de trafego Proxy de tamanho fixo indicando comunicacao C2 (CRITICO). | 
| Nivel 3 (N3) | Correlacao de Dados | Agrupa logs em memoria para identificar conexoes de multiplas origens direcionadas a um unico destino dentro de um curto espaco de tempo. | 

## Padroes de Ameacas Identificados

1. Malware Beaconing / Trafego C2: Requisicoes de saida repetidas no Proxy-Edge-01 para o destino 10.0.0.1 com um tamanho de carga fixo (bytes=2450).

2. Login Privilegiado Incomum: Acesso SSH direto bem-sucedido (accepted) para a conta root no srv-linux-01.

3. Correlacao de Multiplas Origens: Alerta automatico gerado quando multiplos IPs de origem diferentes acessam 10.0.0.1 simultaneamente.

## Como Executar

### Pre-requisitos

* Java Development Kit (JDK): Versao 17 ou superior (testado no JDK 23)

* IDE: IntelliJ IDEA, Eclipse ou VS Code

### Execucao

1. Clone este repositorio:

   ```
   git clone https://github.com/seu-usuario/analise-logs-soc.git
   
   ```

2. Abra o projeto na sua IDE Java de preferencia.

3. Execute o arquivo Main.java.

## Exemplo de Saida no Terminal

```text
=== INICIANDO ANÁLISE DE LOGS ===

[10:00:01] Host: Proxy-Edge-01 | Origem: 10.0.0.24 -> Destino: 10.0.0.1 | Classificação: CRÍTICO - N2: Possível Malware Beaconing / C2 (Tráfego padronizado)
[10:00:02] Host: srv-linux-01 | Origem: 10.0.0.48 -> Destino: 10.0.1.5 | Classificação: ALTO - N2: Login de Root aceito fora do padrão
[10:00:03] Host: SRV-WEB-01 | Origem: 10.0.0.15 -> Destino: 10.0.1.10 | Classificação: INFO - N1: Tráfego Normal
[10:00:04] Host: Proxy-Edge-01 | Origem: 10.0.0.83 -> Destino: 10.0.0.1 | Classificação: CRÍTICO - N2: Possível Malware Beaconing / C2 (Tráfego padronizado)

=== CORRELAÇÃO DE DADOS (N3) ===
ALERTA DE CORRELAÇÃO: O IP destino 10.0.0.1 recebeu 2 conexões em curto período!

Process finished with exit code 0
```

## Tecnologias Utilizadas

* Linguagem: Java

* Conceitos: Stream API, Expressoes Regulares (Regex), Pattern Matching, Agrupamento e Correlacao de Dados, Records.
