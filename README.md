## Your own tunnel -- 🐰 Rabbit - Your Own Private Tunnel System

**Repository**: [https://github.com/SyneHQ/rabbit.go](https://github.com/SyneHQ/rabbit.go)

![](./assets/img/banner.jpg)

## 🎯 Why We Built This

So here's the story. We run this data platform called **Syne** where people can query their databases, visualize data, run analytics, and ask our AI questions about their datasets. Pretty cool stuff, right?

But we hit a problem. Our users' databases and containers are running **locally** on their machines or private networks - not exposed to the internet (which is actually smart security-wise). So how do they connect their local PostgreSQL, MySQL, or whatever database to our cloud platform without opening up their firewall to the world?

That's where **rabbit** comes in.

## 🚇 What Rabbit Actually Does

Think of rabbit as your personal, private version of ngrok - but built specifically for **production use** and **private networks**. No more sketchy public tunnels or trusting third-party services with your sensitive database connections.

Here's how it works in practice:

1. **You run rabbit server** on a VPS or cloud instance you control
2. **Your users run rabbit client** on their local machines with a token you give them  
3. **Boom!** Their local database is now accessible through a persistent port on your server
4. **Your platform** (like Syne) connects to that port and can query their data securely

## 🔐 The Token System (Because Security Matters)

We're not messing around with security here. Every connection needs a **token** that you generate and distribute:

- **Admins** use the rabbit server's API to create tokens
- **Teams** can have multiple tokens (perfect for different environments)
- **One token = one persistent port** - no sharing, no conflicts
- **Want to free up a port?** Delete the token. That's it.

This means you have complete control over who can tunnel what, and tokens can't step on each other's toes.

## 🚀 Real-World Usage

We've battle-tested this thing:

✅ **Private networks**: Works beautifully. No firewall nonsense needed.  
✅ **Public networks**: Yep, tested that too. Handles the crazy internet just fine.  
✅ **Production workloads**: Database connections, web services, APIs - all good.  
✅ **Multiple users**: Teams can run concurrent tunnels without conflicts.

## Architecture

For a full technical breakdown, see [TUNNEL_SYSTEM_SUMMARY.md](./TUNNEL_SYSTEM_SUMMARY.md)

## 🛠️ Quick Start

### Server Setup (Run this on your VPS)
```bash
# Clone and build
git clone https://github.com/SyneHQ/rabbit.go
cd rabbit.go/server
go build -o rabbit.go

# Start the server
./rabbit.go server --bind 0.0.0.0 --port 9999 --api-port 3422
```

### Client Setup (Your users run this) (thing that lives in /client folder)
```bash
# Connect their local database
./rabbit.go tunnel --server your-server.com:9999 --local-port 5432 --token their-token-here
```

### Generate Tokens (Admin)
```bash
# Create team and tokens via API
curl -X POST http://localhost:3422/api/teams -d '{"name":"Development Team"}'
curl -X POST http://localhost:3422/api/tokens -d '{"team":"Development Team"}'
```

## 🎯 Perfect For

- **Data platforms** like Syne that need secure access to user databases
- **Development teams** sharing local services securely  
- **Staging environments** that need to connect to production-like data
- **Analytics platforms** accessing private datasets
- **Any use case** where you need reliable, private tunneling

## 🔥 Why Not Just Use ngrok?

Good question! Here's why we built our own:

| ngrok | rabbit |
|-------|--------|
| 🤷‍♂️ Trust a third party | 🔒 **You control everything** |
| 💸 Pay per tunnel | 💰 **Free (your infrastructure)** |
| 🌐 Public subdomains | 🏠 **Private persistent ports** |
| 📊 Limited logs/control | 📈 **Full monitoring & APIs** |
| 🎲 Session-based | 💾 **Database-backed persistence** |

## 🚧 Production Features

This isn't just a toy project. Rabbit includes:

- **🔄 Auto-restoration**: Server restarts? Tunnels automatically restore
- **🔗 Seamless reconnection**: Clients reconnect without port conflicts  
- **📊 Database logging**: All connections tracked and monitored
- **🐳 Docker ready**: Production deployment with containers
- **🔍 Health checks**: API endpoints for monitoring
- **⚡ Redis caching**: Fast session management

## 🤝 Contributing

Found a bug? Want a feature? We're open to contributions! Check out our [GitHub repo](https://github.com/SyneHQ/rabbit.go) and feel free to open issues or submit PRs.

## 📜 License

MIT License - use it however you want. See [LICENSE](LICENSE) for details.

---

**Built with ❤️ by the team at SyneHQ for anyone who needs reliable, private tunneling.** 