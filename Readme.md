📌 Spring Cloud Config - Centralizando Configurações (Java 21+)

Em um exemplo anterior apresentei boas práticas com @ConfigurationProperties no Spring Boot (Java 21+), neste, abordo um pouco sobre Spring Cloud Config


🚀 O que é o Spring Cloud Config?

O Spring Cloud Config fornece um servidor central de configuração, geralmente integrado a um repositório Git, permitindo que aplicações cliente carreguem suas configurações de forma remota, padronizada e segura.


✅ Benefícios:

- Centralização das configurações
- Separação entre código e configuração
- Suporte a múltiplos ambientes (dev, test, prod)
- Suporte à criptografia de propriedades sensíveis ({cipher})

🚀 Vamos pra prática?

📁 Crie um repo (Azure, Gitlab, GitHub, etc) só para os arquivos properties (ou yml) das aplicações com a seguinte estrutura de pastas:

├── properties/
│   └── NOME_DA_APLICACAO
│         └── PROFILE

Onde NOME_DA_APLICACAO deve ser IGUAL ao que está no properties da aplicação em spring.application.name. E PROFILE deve ser o profile do properties de acordo com o ambiente: dev, hml (staging) ou prod

Para este exemplo ficará assim:

├── properties/
│   └── cloudconfigpropclient
│         └── development
│         └── staging
│         └── production

🛠️ Copie o properties da aplicação para dentro da pasta de acordo com os valores para cada profile (ambiente):

├── properties/
│   └── cloudconfigpropclient
│         └── development
│               └── application.properties
│         └── staging
│         └── production

⚙️ Execute o exemplo (projeto Exemplo-Cloud-Config-Server) do Cloud Config Server localmente, e faça o teste no browser (ou Postman):

http://localhost:8888/cloudconfigpropserver/config/cloudconfigpropclient/development

🧠 Deve retornar os valores do properties que adiciononou na pasta

⚙️ Execute o exemplo (projeto Exemplo-Cloud-Config-Client) do Cloud Config Client localmente, e faça o teste no browser (ou Postman):

http://localhost:8080/api/config

🧠 Dever retornar o response do controler com os valores lidos no properties

🧵 Conclusão

Spring Cloud Config é uma ferramenta poderosa para centralizar, versionar e proteger configurações em ambientes distribuídos. Com suporte a criptografia, você consegue manter dados sensíveis seguros mesmo com repositórios públicos.

Para projetos GitOps ou ambientes mais avançados, considere:

- Sealed Secrets
- External Secrets Operator
- Spring Cloud Vault

🔐 Para criptografar dados sensíveis

1) Use o Swagger ou o Postman, envie via POST para o endpoint /certificate o nome da aplicação client (spring.application.name do properties da aplicação client), gere os arquivos dos certificados (pfx) para cada ambiente e o arquivo das senhas dos certificados (claro que não é pra deixar no git esse arquivo né??!!)

2) Copie o certificado para a pasta /certs da aplicação client (aquela que irá consumir o properties):
<img width="382" height="220" alt="image" src="https://github.com/user-attachments/assets/7ae63cf6-0dcd-4534-9790-3d6d736849ba" />

3) Configure o properties da aplicação client, com o caminho para o certificado, e variável de ambiente com a senha do certificado (não vai colocar a senha diretamente no properties do client né???!!!)

4) Copie a chave pública (pem) de cada ambiente, gerada no passo 1, para o repo dos properties, na pasta da aplicação e do ambiente (ex.: properties/cloudconfigpropclient/development/cloudconfigpropclient-client-key-development.pem). A chave pública não é segredo e pode ficar no Git.

5) Para criptografar o dado sensível, use o endpoint /certificate/encrypt no Config Server, informando o nome da aplicação (applicationName), o ambiente (profile) e o valor (data). O Config Server busca a chave pública no repo dos properties, então não é preciso enviar arquivo nenhum. Opcionalmente informe a branch (label); sem ela, é usada a branch padrão do Config Server. Também é possível enviar o arquivo pem direto no endpoint /certificate/pem/encrypt. Em ambos os casos basta a chave pública: a chave privada (pfx) e a senha ficam somente com a aplicação client, que é quem descriptografa. Se tiver só o pfx, recupere a chave pública pelo endpoint /certificate/pfx/public-key/export.

6) Copie o dado criptografado (com o prefixo {cipher}) que foi gerado, para o properties da aplicação, e para o ambiente desejado. Lembrando que é o properties que fica no repo dos properties, e não diretamente em qualquer aplicação.

7) Todos os exemplos do uso do dado criptografado se encontram nos meus repositórios
