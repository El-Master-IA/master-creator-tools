import { mkdir, mkdtemp, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MctError } from "@mct/contract/errors";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	detectSyncedFolder,
	guardSyncedDestination,
} from "../src/init-guards.js";

const cases: Array<[string, string, string]> = [
	["OneDrive", "C:\\Users\\ana\\OneDrive\\proyectos", "onedrive"],
	["OneDrive empresa", "C:\\Users\\ana\\OneDrive - Acme SA\\x", "onedrive"],
	["OneDrive POSIX", "/home/ana/OneDrive/proyectos", "onedrive"],
	[
		"OneDrive macOS",
		"/Users/ana/Library/CloudStorage/OneDrive-Acme/x",
		"onedrive",
	],
	["Dropbox win", "D:\\Dropbox\\clientes", "dropbox"],
	["Dropbox POSIX", "/home/ana/Dropbox (Personal)/clientes", "dropbox"],
	[
		"iCloud macOS",
		"/Users/ana/Library/Mobile Documents/com~apple~CloudDocs/x",
		"icloud",
	],
	["iCloud win", "C:\\Users\\ana\\iCloudDrive\\x", "icloud"],
	["iCloud espacio", "C:\\Users\\ana\\iCloud Drive\\x", "icloud"],
	["Google Drive", "/Users/ana/Google Drive/Mi unidad/x", "google-drive"],
	[
		"Google Drive CloudStorage",
		"/Users/ana/Library/CloudStorage/GoogleDrive-ana@x.co/My Drive/x",
		"google-drive",
	],
	["Google Drive letra", "G:\\My Drive\\x", "google-drive"],
	["Shared drives", "G:\\Shared drives\\Equipo\\x", "google-drive"],
	[
		"Unidades compartidas",
		"G:\\Unidades compartidas\\Equipo\\x",
		"google-drive",
	],
	["Meu Drive", "G:\\Meu Drive\\x", "google-drive"],
	["Mi unidad win", "G:\\Mi unidad\\x", "google-drive"],
	["mayusculas", "C:\\USERS\\ANA\\ONEDRIVE\\X", "onedrive"],
];

describe("CLI-006 deteccion de carpeta sincronizada", () => {
	it.each(cases)("CLI-006 detecta %s", (_n, ruta, proveedor) => {
		expect(detectSyncedFolder(ruta)?.proveedor).toBe(proveedor);
	});

	it("CLI-006 no marca carpetas locales ni nombres parecidos", () => {
		for (const r of [
			"C:\\Users\\ana\\proyectos",
			"/home/ana/work",
			"/home/ana/mydropboxnotes/x",
			"/home/ana/onedrive-notes/x",
			"/srv/data/Drive",
		]) {
			expect(detectSyncedFolder(r)).toBeNull();
		}
	});

	it("CLI-006 usa las variables de entorno de OneDrive con otra ubicacion", () => {
		const env = { OneDrive: "D:\\Nube\\Trabajo" };
		expect(detectSyncedFolder("D:\\Nube\\Trabajo\\x", { env })?.proveedor).toBe(
			"onedrive",
		);
		expect(detectSyncedFolder("D:\\Nube\\Otro\\x", { env })).toBeNull();
		expect(detectSyncedFolder("D:\\Nube\\TrabajoX\\x", { env })).toBeNull();
	});

	it("CLI-006 la deteccion no depende del SO que corre", () => {
		expect(detectSyncedFolder("C:/Users/ana/Dropbox/x")?.proveedor).toBe(
			"dropbox",
		);
		expect(detectSyncedFolder("\\\\srv\\share\\OneDrive\\x")?.proveedor).toBe(
			"onedrive",
		);
	});
});

describe("CLI-006 guarda del destino", () => {
	let base: string;
	beforeEach(async () => {
		base = await mkdtemp(join(tmpdir(), "mct-t41-"));
	});
	afterEach(async () => {
		await rm(base, { recursive: true, force: true });
	});

	it("CLI-006 sin TTY y sincronizado sale con CANCELADO sin copiar", async () => {
		const dest = join(base, "OneDrive", "proyecto");
		await mkdir(join(base, "OneDrive"), { recursive: true });
		const confirmar = vi.fn(async () => true);
		const err = await guardSyncedDestination({
			dest,
			isTTY: false,
			confirmar,
		}).catch((e: unknown) => e);
		expect(err).toBeInstanceOf(MctError);
		expect((err as MctError).codigo).toBe("CANCELADO");
		expect((err as MctError).exit).toBe(20);
		expect((err as MctError).accion).toContain("--dest");
		expect(confirmar).not.toHaveBeenCalled();
		expect(await readdir(join(base, "OneDrive"))).toEqual([]);
	});

	it("CLI-006 con TTY pide confirmacion; rechazar cancela", async () => {
		const dest = join(base, "Dropbox", "p");
		const confirmar = vi.fn(async () => false);
		await expect(
			guardSyncedDestination({ dest, isTTY: true, confirmar }),
		).rejects.toMatchObject({ codigo: "CANCELADO" });
		expect(confirmar).toHaveBeenCalledOnce();
	});

	it("SEG-209 solo ok === true confirma; un Symbol de cancelacion cancela", async () => {
		const dest = join(base, "Dropbox", "p");
		for (const value of [Symbol("clack:cancel"), "yes", 1, {}, undefined]) {
			await expect(
				guardSyncedDestination({
					dest,
					isTTY: true,
					confirmar: (async () => value) as unknown as () => Promise<boolean>,
				}),
			).rejects.toMatchObject({ codigo: "CANCELADO" });
		}
	});

	it("CLI-006 con TTY y confirmacion sigue", async () => {
		const dest = join(base, "Dropbox", "p");
		const r = await guardSyncedDestination({
			dest,
			isTTY: true,
			confirmar: async () => true,
		});
		expect(r).toMatchObject({ sincronizado: true, proveedor: "dropbox" });
	});

	it("CLI-006 con TTY pero sin confirmador cancela (no asume si)", async () => {
		await expect(
			guardSyncedDestination({
				dest: join(base, "iCloudDrive", "p"),
				isTTY: true,
			}),
		).rejects.toMatchObject({ codigo: "CANCELADO" });
	});

	it("CLI-006 destino local pasa sin preguntar", async () => {
		const confirmar = vi.fn(async () => true);
		const r = await guardSyncedDestination({
			dest: join(base, "local"),
			isTTY: false,
			confirmar,
		});
		expect(r.sincronizado).toBe(false);
		expect(confirmar).not.toHaveBeenCalled();
	});

	it("CLI-006 el mensaje respeta --lang", async () => {
		const dest = join(base, "OneDrive", "p");
		const es = await guardSyncedDestination({
			dest,
			isTTY: false,
			lang: "es",
		}).catch((e: unknown) => e as MctError);
		const en = await guardSyncedDestination({
			dest,
			isTTY: false,
			lang: "en",
		}).catch((e: unknown) => e as MctError);
		expect((es as MctError).message).toContain("No se copió nada");
		expect((en as MctError).message).toContain("Nothing was copied");
	});
});
