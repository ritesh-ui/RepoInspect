const { exec } = require('child_process');
const { ChatOpenAI } = require('@langchain/openai');

/**
 * Vulnerable Command Injection
 * Data flow: user_input -> cmd -> exec
 * This should be caught by Tree-Sitter AST Taint Analysis
 */
function runUserCommand(user_input) {
    const cmd = "echo " + user_input;
    exec(cmd, (error, stdout, stderr) => {
        console.log(stdout);
    });
}

/**
 * Safe Usage
 * Regex might flag "exec" but AST should see no tainted data flow
 */
function safeInternalTask() {
    const internalCmd = "ls -la";
    exec(internalCmd, (error) => {});
}

/**
 * AI Security Risk (Prompt Injection)
 * Data flow: userInput -> prompt -> model.invoke
 */
async function runAgent(userInput) {
    const model = new ChatOpenAI({ openAIApiKey: process.env.OPENAI_API_KEY });
    const prompt = `System: Summarize this: ${userInput}`;
    const response = await model.invoke(prompt);
    return response;
}
