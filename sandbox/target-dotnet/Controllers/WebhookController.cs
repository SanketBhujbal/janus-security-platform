using Microsoft.AspNetCore.Mvc;
using TargetDotnet.Models;

namespace TargetDotnet.Controllers;

[ApiController]
[Route("api/[controller]")]
public class WebhookController : ControllerBase
{
    private readonly PaymentsDb _db;
    public WebhookController(PaymentsDb db) { _db = db; }

    // SEEDED: payments.dotnet.webhook-amount-trust
    // Gateway callback whose `amount` field is trusted blindly. A spoofed
    // (or replayed-with-edit) webhook can mark a $1 order as $1000 paid.
    [HttpPost("gateway")]
    public async Task<IActionResult> Gateway([FromBody] GatewayCallback webhook)
    {
        var order = _db.Orders.Find(webhook.OrderId);
        if (order == null) return NotFound();

        order.Amount = webhook.Amount;
        order.Status = "settled";
        await _db.SaveChangesAsync();
        return Ok();
    }
}

public record GatewayCallback(string OrderId, decimal Amount, string Signature);
