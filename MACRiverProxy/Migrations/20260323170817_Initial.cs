using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace MACRiverProxy.Migrations
{
    /// <inheritdoc />
    public partial class Initial : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.CreateTable(
                name: "ActiveTokens",
                columns: table => new
                {
                    Key = table.Column<string>(type: "TEXT", nullable: false),
                    ExpireTime = table.Column<DateTime>(type: "TEXT", nullable: false)
                },
                constraints: table =>
                {
                    table.PrimaryKey("PK_ActiveTokens", x => x.Key);
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "ActiveTokens");
        }
    }
}
