# T1027.010 - Obfuscated Files or Information: Command Obfuscation

Adversaries may obfuscate content during command execution to impede detection. Command-line obfuscation is a method of making strings and patterns within commands and scripts more difficult to signature and analyze. This type of obfuscation can be included within commands executed by delivered payloads (e.g., Phishing and Drive-by Compromise) or interactively via Command and Scripting Interpreter.

For example, adversaries may abuse syntax that utilizes various symbols and escape characters (such as spacing, ^, +. $, and %) to make commands difficult to analyze while maintaining the same intended functionality. Many languages support built-in obfuscation in the form of base64 or URL encoding. Adversaries may also manually implement command obfuscation via string splitting ("Wor"+"d.Application"), order and casing of characters (rev <<<'dwssap/cte/ tac'), globing (mkdir -p '/tmp/:&$NiA'), as well as various tricks involving passing strings through tokens/environment variables/input streams.

Adversaries may also use tricks such as directory traversals to obfuscate references to the binary being invoked by a command (C:\voi\pcw\..\..\Windows\tei\qs\k\..\..\..\system32\erool\..\wbem\wg\je\..\..\wmic.exe shadowcopy delete).

Tools such as Invoke-Obfuscation and Invoke-DOSfucation have also been used to obfuscate commands.
