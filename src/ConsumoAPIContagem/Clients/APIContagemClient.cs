using ConsumoAPIContagem.Extensions;
using ConsumoAPIContagem.Interfaces;
using ConsumoAPIContagem.Models;
using Microsoft.Extensions.Configuration;
using Polly;
using Polly.Retry;
using Refit;
using Serilog.Core;
using System.Net;
using System.Text.Json;
using System.Text;

namespace ConsumoAPIContagem.Clients;

public class APIContagemClient : IDisposable
{
    private ILoginAPI? _loginAPI;
    private IContagemAPI? _contagemAPI;
    private IConfiguration? _configuration;
    private Logger? _logger;
    private Token? _token;
    private AsyncRetryPolicy? _jwtPolicy;
    private JsonSerializerOptions? _serializerOptions;
    private Jose.Jwk _tokenDecryptionKey;

    public bool IsAuthenticatedUsingToken
    {
        get => _token?.Authenticated ?? false;
    }

    public APIContagemClient(IConfiguration configuration,
        Logger logger)
    {
        _configuration = configuration;
        _logger = logger;

        string urlBase = _configuration["APIContagem_Access:UrlBase"]!;

        _loginAPI = RestService.For<ILoginAPI>(urlBase);
        _contagemAPI = RestService.For<IContagemAPI>(urlBase);
        _jwtPolicy = CreateAccessTokenPolicy();
        _serializerOptions = new JsonSerializerOptions() { WriteIndented = true };
        _tokenDecryptionKey = new Jose.Jwk(
            Encoding.UTF8.GetBytes(_configuration["APIContagem_Access:TokenDecryptionKey"]!));
    }

    public async Task Autenticar()
    {
        try
        {
            // Envio da requisição a fim de autenticar
            // e obter o token de acesso
            _token = await _loginAPI!.PostCredentialsAsync(
                new ()
                {
                    UserID = _configuration!.GetSection("APIContagem_Access:UserID").Value,
                    Password = _configuration.GetSection("APIContagem_Access:Password").Value
                });
            _logger!.Information("Token JWE:" +
                Environment.NewLine +
                FormatJSONPayload<Token>(_token));

            var decryptedToken = Jose.JWE.Decrypt(_token.AccessToken, _tokenDecryptionKey,
                Jose.JweAlgorithm.A128KW, Jose.JweEncryption.A128CBC_HS256);
            _logger.Information($"PlainText (Token sem criptografia:{Environment.NewLine}" +
                decryptedToken.Plaintext);

            _logger.Information("Payload do Access Token:" + Environment.NewLine +
                FormatJSONPayload<PayloadAccessToken>(
                    Jose.JWT.Payload<PayloadAccessToken>(decryptedToken.Plaintext)));
        }
        catch
        {
            _token = null;
            _logger!.Error("Falha ao autenticar...");
        }
    }

    private string FormatJSONPayload<T>(T payload) =>
        JsonSerializer.Serialize(payload, _serializerOptions);

    private AsyncRetryPolicy CreateAccessTokenPolicy()
    {
        return Policy
            .HandleInner<ApiException>(
                ex => ex.StatusCode == HttpStatusCode.Unauthorized)
            .RetryAsync(1, async (ex, retryCount, context) =>
            {
                var corAnterior = Console.ForegroundColor;

                Console.ForegroundColor = ConsoleColor.Red;
                await Console.Out.WriteLineAsync(
                    Environment.NewLine + "Token expirado ou usuário sem permissão!");
                Console.ForegroundColor = corAnterior;

                Console.ForegroundColor = ConsoleColor.Green;
                await Console.Out.WriteLineAsync(
                    Environment.NewLine + "Execução de RetryPolicy..." +
                    Environment.NewLine);
                Console.ForegroundColor = corAnterior;

                await Autenticar();
                if (!(_token?.Authenticated ?? false))
                    throw new InvalidOperationException("Token inválido!");

                context["AccessToken"] = _token.AccessToken;
            });
    }

    public async Task ExibirResultadoContador()
    {
        var retorno = await _jwtPolicy!.ExecuteWithTokenAsync<ResultadoContador>(
            _token!, async (context) =>
        {
            var resultado = await _contagemAPI!.ObterValorAtualAsync(
              $"Bearer {context["AccessToken"]}");
            return resultado;
        });
        _logger!.Information("Retorno da API de Contagem: " +
            Environment.NewLine +
            FormatJSONPayload<ResultadoContador>(retorno));
    }

    public void Dispose()
    {
        _loginAPI = null;
        _contagemAPI = null;
        _configuration = null;
        _logger = null;
        _token = null;
        _jwtPolicy = null;
        _serializerOptions = null;
    }
}