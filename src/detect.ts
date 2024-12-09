import { readFile } from 'node:fs/promises';

export async function detect(file: string) {
    const buffer = await readFile(file);

    if (buffer[0] === 0x4D && buffer[1] === 0x5A) {
        return "pe";
    } else return null;
}