const path = require('path');

// Use require.resolve for React aliases so they work in both monorepo and standalone setups
const aliases = {
    react: path.resolve(__dirname, 'node_modules/react'),
    'react-dom': path.resolve(__dirname, 'node_modules/react-dom'),
};

module.exports = {
    entry: {
        main: './src/index.tsx',
    },
    devtool: 'source-map',
    externals: {
        babel: 'babel',
        'react-window': 'react-window',
    },
    resolve: {
        extensions: ['.js', '.jsx', '.ts', '.tsx', '.json'],
        alias: aliases,
    },
    module: {
        rules: [
            {
                test: /\.(tsx?)$/,
                loader: 'ts-loader',
                options: {
                    transpileOnly: true,
                    configFile: 'tsconfig.json',
                },
                exclude: /node_modules/,
            },
            {
                test: /\.(css)$/,
                use: ['style-loader', 'css-loader'],
                exclude: /node_modules/,
            },
        ],
    },
    output: {
        filename: '[name].js',
        path: path.resolve(__dirname, 'dist'),
        publicPath: '',
    },
    mode: 'development',
};
