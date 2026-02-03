import asyncio
import struct

USERNAME = b"rashgin"
PASSWORD = b"2007"

async def handle_client(reader, writer):
    try:
        # --- Greeting ---
        ver, nmethods = struct.unpack("!BB", await reader.readexactly(2))
        methods = await reader.readexactly(nmethods)
        writer.write(b"\x05\x02")  # SOCKS5 + Username/Password
        await writer.drain()

        # --- Auth ---
        ver = (await reader.readexactly(1))[0]
        ulen = (await reader.readexactly(1))[0]
        uname = await reader.readexactly(ulen)
        plen = (await reader.readexactly(1))[0]
        passwd = await reader.readexactly(plen)

        if uname != USERNAME or passwd != PASSWORD:
            writer.write(b"\x01\x01")  # auth fail
            await writer.drain()
            writer.close()
            return

        writer.write(b"\x01\x00")  # auth ok
        await writer.drain()

        # --- Request ---
        ver, cmd, _, atyp = struct.unpack("!BBBB", await reader.readexactly(4))
        if cmd != 1:
            writer.close()
            return

        if atyp == 1:  # IPv4
            addr = await reader.readexactly(4)
            address = ".".join(map(str, addr))
        elif atyp == 3:  # Domain
            length = (await reader.readexactly(1))[0]
            address = (await reader.readexactly(length)).decode()
        else:
            writer.close()
            return

        port = struct.unpack("!H", await reader.readexactly(2))[0]

        remote_reader, remote_writer = await asyncio.open_connection(address, port)

        writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()

        async def pipe(src, dst):
            try:
                while True:
                    data = await src.read(4096)
                    if not data:
                        break
                    dst.write(data)
                    await dst.drain()
            except:
                pass
            finally:
                dst.close()

        await asyncio.gather(
            pipe(reader, remote_writer),
            pipe(remote_reader, writer)
        )

    except:
        writer.close()

async def main():
    server = await asyncio.start_server(handle_client, "0.0.0.0", 1080)
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
