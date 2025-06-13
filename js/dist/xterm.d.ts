import { Terminal } from '@xterm/xterm';
export declare class Xterm {
    elem: HTMLElement;
    term: Terminal;
    resizeListener: () => void;
    message: HTMLElement;
    messageTimeout: number;
    messageTimer: number;
    constructor(elem: HTMLElement);
    info(): {
        columns: number;
        rows: number;
    };
    output(data: string): void;
    showMessage(message: string, timeout: number): void;
    removeMessage(): void;
    setWindowTitle(title: string): void;
    setPreferences(value: object): void;
    onInput(callback: (input: string) => void): void;
    onResize(callback: (columns: number, rows: number) => void): void;
    deactivate(): void;
    reset(): void;
    close(): void;
}
