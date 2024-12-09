export const colors = {
    //formatting
    bold: (text: string) => `\x1b[1m${text}\x1b[22m`,

    //colors
    red: (text: string) => `\x1b[31m${text}\x1b[39m`,
    gray: (text: string) => `\x1b[90m${text}\x1b[39m`
};
