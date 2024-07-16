using Microsoft.Extensions.Configuration;
using Serilog;
using ConsumoAPIContagem.Clients;

var builder = new ConfigurationBuilder()
        .SetBasePath(Directory.GetCurrentDirectory())
        .AddJsonFile($"appsettings.json");
var config = builder.Build();
var logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateLogger();

logger.Information("***** Testes com JWE + Refit + Polly (Retry Policy) *****");
logger.Information("A API consumida está em: " +
    Environment.NewLine +
    "https://github.com/renatogroffe/SegurancaAPIs_DevOpsExperience-2024-06");

using var apiContagemClient = new APIContagemClient(config, logger);
await apiContagemClient.Autenticar();
while (true)
{
    await apiContagemClient.ExibirResultadoContador();
    logger.Information("Pressione qualquer tecla para continuar...");
    Console.ReadKey();
}