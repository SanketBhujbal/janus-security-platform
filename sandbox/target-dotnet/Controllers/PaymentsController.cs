using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TargetDotnet.Models;

namespace TargetDotnet.Controllers;

[ApiController]
[Route("api/[controller]")]
public class PaymentsController : ControllerBase
{
    private readonly PaymentsDb _db;
    private readonly ILogger<PaymentsController> _logger;

    public PaymentsController(PaymentsDb db, ILogger<PaymentsController> logger)
    {
        _db = db;
        _logger = logger;
    }

    // SEEDED: payments.dotnet.amount-tampering AND payments.dotnet.pan-cvv-logging
    //         AND payments.dotnet.missing-idempotency
    [HttpPost("charge")]
    public IActionResult Charge(PaymentRequest model)
    {
        // BAD: trusts client amount with no order reconciliation
        var tx = new Transaction
        {
            OrderId = model.OrderId,
            Amount = model.Amount,
            Pan = model.Pan,
            Cvv = model.Cvv,
        };

        // BAD: logs PAN + CVV
        _logger.LogInformation("Charging order={OrderId} pan={Pan} cvv={Cvv} amount={Amount}",
            model.OrderId, model.Pan, model.Cvv, model.Amount);

        // BAD: no idempotency key check before insert
        _db.Transactions.Add(tx);
        _db.SaveChanges();

        return Ok(new { transactionId = tx.Id, status = "approved" });
    }

    // SEEDED: payments.dotnet.broken-authz-idor -- no ownership check
    [HttpGet("account/{id:int}")]
    public IActionResult GetAccount(int id)
    {
        var account = _db.Accounts.FirstOrDefault(x => x.Id == id);
        if (account == null) return NotFound();
        return Ok(account);
    }

    // SEEDED: payments.dotnet.ef-raw-sql-injection -- interpolated FromSqlRaw
    [HttpGet("search")]
    public IActionResult Search(string username)
    {
        var users = _db.Users
            .FromSqlRaw($"SELECT * FROM Users WHERE Username LIKE '%{username}%'")
            .ToList();
        return Ok(users);
    }
}

public record PaymentRequest(string OrderId, decimal Amount, string Pan, string Cvv);
