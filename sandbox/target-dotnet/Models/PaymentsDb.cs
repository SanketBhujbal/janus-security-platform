using Microsoft.EntityFrameworkCore;

namespace TargetDotnet.Models;

public class PaymentsDb : DbContext
{
    public PaymentsDb(DbContextOptions<PaymentsDb> opts) : base(opts) { }
    public DbSet<Transaction> Transactions => Set<Transaction>();
    public DbSet<Account> Accounts => Set<Account>();
    public DbSet<Order> Orders => Set<Order>();
    public DbSet<User> Users => Set<User>();
}

public class Transaction
{
    public int Id { get; set; }
    public string OrderId { get; set; } = "";
    public decimal Amount { get; set; }
    public string Pan { get; set; } = "";
    public string Cvv { get; set; } = "";
}

public class Account
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public decimal Balance { get; set; }
}

public class Order
{
    public string Id { get; set; } = "";
    public decimal Amount { get; set; }
    public string Status { get; set; } = "";
}

public class User
{
    public int Id { get; set; }
    public string Username { get; set; } = "";
}
