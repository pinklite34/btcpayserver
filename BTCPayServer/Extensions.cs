using BTCPayServer.Authentication;
using BTCPayServer.Configuration;
using Microsoft.AspNetCore.Html;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Encodings.Web;
using NBitcoin;
using System.Threading.Tasks;
using NBXplorer;
using NBXplorer.Models;
using System.Linq;
using System.Threading;
using BTCPayServer.Services.Wallets;
using System.IO;
using BTCPayServer.Logging;
using Microsoft.Extensions.Logging;
using System.Net.WebSockets;
using BTCPayServer.Services.Invoices;
using NBitpayClient;
using BTCPayServer.Payments;
using Microsoft.AspNetCore.Identity;
using BTCPayServer.Models;
using System.Security.Claims;
using System.Globalization;
using BTCPayServer.Services;
using BTCPayServer.Data;
using Microsoft.EntityFrameworkCore.Infrastructure;
using LedgerWallet;
using static LedgerWallet.LedgerClient;

namespace BTCPayServer
{
    public static class Extensions
    {
        public static string PrettyPrint(this TimeSpan expiration)
        {
            StringBuilder builder = new StringBuilder();
            if (expiration.Days >= 1)
                builder.Append(expiration.Days.ToString(CultureInfo.InvariantCulture));
            if (expiration.Hours >= 1)
                builder.Append(expiration.Hours.ToString("00", CultureInfo.InvariantCulture));
            builder.Append($"{expiration.Minutes.ToString("00", CultureInfo.InvariantCulture)}:{expiration.Seconds.ToString("00", CultureInfo.InvariantCulture)}");
            return builder.ToString();
        }
        public static decimal RoundUp(decimal value, int precision)
        {
            for (int i = 0; i < precision; i++)
            {
                value = value * 10m;
            }
            value = Math.Ceiling(value);
            for (int i = 0; i < precision; i++)
            {
                value = value / 10m;
            }
            return value;
        }
        public static PaymentMethodId GetpaymentMethodId(this InvoiceCryptoInfo info)
        {
            return new PaymentMethodId(info.CryptoCode, Enum.Parse<PaymentTypes>(info.PaymentType));
        }
        public static async Task CloseSocket(this WebSocket webSocket)
        {
            try
            {
                if (webSocket.State == WebSocketState.Open)
                {
                    CancellationTokenSource cts = new CancellationTokenSource();
                    cts.CancelAfter(5000);
                    await webSocket.CloseAsync(WebSocketCloseStatus.NormalClosure, "Closing", cts.Token);
                }
            }
            catch { }
            finally { try { webSocket.Dispose(); } catch { } }
        }
        public static bool SupportDropColumn(this Microsoft.EntityFrameworkCore.Migrations.Migration migration, string activeProvider)
        {
            return activeProvider != "Microsoft.EntityFrameworkCore.Sqlite";
        }

        public static bool SupportDropForeignKey(this Microsoft.EntityFrameworkCore.Migrations.Migration migration, string activeProvider)
        {
            return activeProvider != "Microsoft.EntityFrameworkCore.Sqlite";
        }
        public static bool SupportDropForeignKey(this DatabaseFacade facade)
        {
            return facade.ProviderName != "Microsoft.EntityFrameworkCore.Sqlite";
        }

        public static async Task<Dictionary<uint256, TransactionResult>> GetTransactions(this BTCPayWallet client, uint256[] hashes, CancellationToken cts = default(CancellationToken))
        {
            hashes = hashes.Distinct().ToArray();
            var transactions = hashes
                                        .Select(async o => await client.GetTransactionAsync(o, cts))
                                        .ToArray();
            await Task.WhenAll(transactions).ConfigureAwait(false);
            return transactions.Select(t => t.Result).Where(t => t != null).ToDictionary(o => o.Transaction.GetHash());
        }
        public static string WithTrailingSlash(this string str)
        {
            if (str.EndsWith("/", StringComparison.InvariantCulture))
                return str;
            return str + "/";
        }

        public static void SetHeaderOnStarting(this HttpResponse resp, string name, string value)
        {
            if (resp.HasStarted)
                return;
            resp.OnStarting(() =>
            {
                SetHeader(resp, name, value);
                return Task.CompletedTask;
            });
        }

        public static async Task<Transaction> SignTransactionAsyncEx(this LedgerClient client, SignatureRequest[] signatureRequests, Transaction transaction, KeyPath changePath = null, CancellationToken cancellation = default(CancellationToken))
        {
            if (signatureRequests.Length == 0)
                throw new ArgumentException("No signatureRequests is passed", "signatureRequests");
            var segwitCoins = signatureRequests.Where(s => s.InputCoin.GetHashVersion() == HashVersion.Witness).Count();
            if (segwitCoins != signatureRequests.Count() && segwitCoins != 0)
                throw new ArgumentException("Mixing segwit input with non segwit input is not supported", "signatureRequests");

            var segwitMode = segwitCoins != 0;

            var requests = signatureRequests
                .ToDictionaryUnique(o => o.InputCoin.Outpoint);
            transaction = transaction.Clone();
            var inputsByOutpoint = transaction.Inputs.AsIndexedInputs().ToDictionary(i => i.PrevOut);
            var coinsByOutpoint = requests.ToDictionary(o => o.Key, o => o.Value.InputCoin);

            Logs.PayServer.LogInformation("---GETTING TRUSTED INPUTS---");
            var trustedInputs = new List<TrustedInput>();
            if (!segwitMode)
            {
                List<byte[]> trustedInputApdus = new List<byte[]>();
                int i = 0;
                foreach (var sigRequest in signatureRequests)
                {
                    var ti = await client.GetTrustedInputAsync(sigRequest.InputTransaction, (int)sigRequest.InputCoin.Outpoint.N);
                    trustedInputs.Add(ti);
                    Logs.PayServer.LogInformation($"Got input {i++}");
                }
            }
            Logs.PayServer.LogInformation("---GOT THEM---");

            var trustedInputsByOutpoint = trustedInputs.ToDictionaryUnique(i => i.OutPoint);
            var apdus = new List<byte[]>();
            var inputStartType = segwitMode ? InputStartType.NewSegwit : InputStartType.New;


            var segwitParsedOnce = false;
            for (var i = 0; i < signatureRequests.Length; i++)
            {
                var sigRequest = signatureRequests[i];
                var input = inputsByOutpoint[sigRequest.InputCoin.Outpoint];
                apdus.AddRange(client.UntrustedHashTransactionInputStart(inputStartType, input, trustedInputsByOutpoint, coinsByOutpoint, segwitMode, segwitParsedOnce));
                Logs.PayServer.LogInformation($"UntrustedHashTransactionInputStart");
                inputStartType = InputStartType.Continue;
                if (!segwitMode || !segwitParsedOnce)
                {
                    apdus.AddRange(client.UntrustedHashTransactionInputFinalizeFull(changePath, transaction.Outputs));
                    Logs.PayServer.LogInformation($"UntrustedHashTransactionInputFinalizeFull");
                }
                changePath = null; //do not resubmit the changepath
                if (segwitMode && !segwitParsedOnce)
                {
                    segwitParsedOnce = true;
                    i--; //pass once more
                    continue;
                }
                apdus.Add(client.UntrustedHashSign(sigRequest.KeyPath, null, transaction.LockTime, SigHash.All));
                Logs.PayServer.LogInformation($"UntrustedHashSign");
            }
            Logs.PayServer.LogInformation("--SIGNING ALL---");
            var responses = await client.ExchangeAsync(apdus.ToArray(), cancellation).ConfigureAwait(false);
            Logs.PayServer.LogInformation("--SIGNED!---");
            foreach (var response in responses)
                if (response.Response.Length > 10) //Probably a signature
                    response.Response[0] = 0x30;
            var signatures = responses.Where(p => TransactionSignature.IsValid(p.Response)).Select(p => new TransactionSignature(p.Response)).ToArray();
            Logs.PayServer.LogInformation($"With {signatures.Length} signatures");
            if (signatureRequests.Length != signatures.Length)
                throw new LedgerWalletException("failed to sign some inputs");
            var sigIndex = 0;

            var builder = new TransactionBuilder();
            foreach (var sigRequest in signatureRequests)
            {
                var input = inputsByOutpoint[sigRequest.InputCoin.Outpoint];
                if (input == null)
                    continue;
                builder.AddCoins(sigRequest.InputCoin);
                builder.AddKnownSignature(sigRequest.PubKey, signatures[sigIndex]);
                sigIndex++;
            }
            builder.SignTransactionInPlace(transaction);
            Logs.PayServer.LogInformation($"Fully signed");
            sigIndex = 0;
            foreach (var sigRequest in signatureRequests)
            {
                var input = inputsByOutpoint[sigRequest.InputCoin.Outpoint];
                if (input == null)
                    continue;
                sigRequest.Signature = signatures[sigIndex];
                if (!sigRequest.PubKey.Verify(transaction.GetSignatureHash(sigRequest.InputCoin, sigRequest.Signature.SigHash), sigRequest.Signature.Signature))
                {
                    foreach (var sigRequest2 in signatureRequests)
                        sigRequest2.Signature = null;
                    return null;
                }
                sigIndex++;
            }

            return transaction;
        }
        public static async Task<APDUResponse[]> ExchangeAsync(this LedgerClient client, byte[][] apdus, CancellationToken cancellation)
        {
            var responses = await client.Transport.Exchange(apdus, cancellation).ConfigureAwait(false);
            var resultResponses = new List<APDUResponse>();
            foreach (var response in responses)
            {
                if (response.Length < 2)
                {
                    throw new LedgerWalletException("Truncated response");
                }
                var sw = ((response[response.Length - 2] & 0xff) << 8) |
                        response[response.Length - 1] & 0xff;
                var result = new byte[response.Length - 2];
                Array.Copy(response, 0, result, 0, response.Length - 2);
                resultResponses.Add(new APDUResponse() { Response = result, SW = sw });
            }
            return resultResponses.ToArray();
        }

        public static void SetHeader(this HttpResponse resp, string name, string value)
        {
            var existing = resp.Headers[name].FirstOrDefault();
            if (existing != null && value == null)
                resp.Headers.Remove(name);
            else
                resp.Headers[name] = value;
        }

        public static string GetAbsoluteRoot(this HttpRequest request)
        {
            return string.Concat(
                        request.Scheme,
                        "://",
                        request.Host.ToUriComponent(),
                        request.PathBase.ToUriComponent());
        }

        public static string GetCurrentUrl(this HttpRequest request)
        {
            return string.Concat(
                        request.Scheme,
                        "://",
                        request.Host.ToUriComponent(),
                        request.PathBase.ToUriComponent(),
                        request.Path.ToUriComponent());
        }

        public static string GetCurrentPath(this HttpRequest request)
        {
            return string.Concat(
                        request.PathBase.ToUriComponent(),
                        request.Path.ToUriComponent());
        }

        public static string GetAbsoluteUri(this HttpRequest request, string redirectUrl)
        {
            bool isRelative =
                (redirectUrl.Length > 0 && redirectUrl[0] == '/')
                || !new Uri(redirectUrl, UriKind.RelativeOrAbsolute).IsAbsoluteUri;
            return isRelative ? request.GetAbsoluteRoot() + redirectUrl : redirectUrl;
        }

        public static IServiceCollection ConfigureBTCPayServer(this IServiceCollection services, IConfiguration conf)
        {
            services.Configure<BTCPayServerOptions>(o =>
            {
                o.LoadArgs(conf);
            });
            return services;
        }

        public static string GetSIN(this ClaimsPrincipal principal)
        {
            return principal.Claims.Where(c => c.Type == Claims.SIN).Select(c => c.Value).FirstOrDefault();
        }

        public static string GetStoreId(this ClaimsPrincipal principal)
        {
            return principal.Claims.Where(c => c.Type == Claims.OwnStore).Select(c => c.Value).FirstOrDefault();
        }

        public static void SetIsBitpayAPI(this HttpContext ctx, bool value)
        {
            NBitcoin.Extensions.TryAdd(ctx.Items, "IsBitpayAPI", value);
        }

        public static void AddRange<T>(this HashSet<T> hashSet, IEnumerable<T> items)
        {
            foreach (var item in items)
            {
                hashSet.Add(item);
            }
        }
        public static bool GetIsBitpayAPI(this HttpContext ctx)
        {
            return ctx.Items.TryGetValue("IsBitpayAPI", out object obj) &&
                  obj is bool b && b;
        }

        public static void SetBitpayAuth(this HttpContext ctx, (string Signature, String Id, String Authorization) value)
        {
            NBitcoin.Extensions.TryAdd(ctx.Items, "BitpayAuth", value);
        }

        public static async Task<T> WithCancellation<T>(this Task<T> task, CancellationToken cancellationToken)
        {
            using (var delayCTS = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                var waiting = Task.Delay(-1, delayCTS.Token);
                var doing = task;
                await Task.WhenAny(waiting, doing);
                delayCTS.Cancel();
                cancellationToken.ThrowIfCancellationRequested();
                return await doing;
            }
        }
        public static async Task WithCancellation(this Task task, CancellationToken cancellationToken)
        {
            using (var delayCTS = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
            {
                var waiting = Task.Delay(-1, delayCTS.Token);
                var doing = task;
                await Task.WhenAny(waiting, doing);
                delayCTS.Cancel();
                cancellationToken.ThrowIfCancellationRequested();
            }
        }

        public static (string Signature, String Id, String Authorization) GetBitpayAuth(this HttpContext ctx)
        {
            ctx.Items.TryGetValue("BitpayAuth", out object obj);
            return ((string Signature, String Id, String Authorization))obj;
        }

        public static StoreData GetStoreData(this HttpContext ctx)
        {
            return ctx.Items.TryGet("BTCPAY.STOREDATA") as StoreData;
        }
        public static void SetStoreData(this HttpContext ctx, StoreData storeData)
        {
            ctx.Items["BTCPAY.STOREDATA"] = storeData;
        }

        private static JsonSerializerSettings jsonSettings = new JsonSerializerSettings { ContractResolver = new CamelCasePropertyNamesContractResolver() };
        public static string ToJson(this object o)
        {
            var res = JsonConvert.SerializeObject(o, Formatting.None, jsonSettings);
            return res;
        }
    }
}
