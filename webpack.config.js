const path = require('path');
const { ProvidePlugin } = require('webpack');
const CopyPlugin = require('copy-webpack-plugin');

module.exports = {
  entry: {
    dashboard: './src/dashboard.js',
    background: './src/background.js',
    content: './src/content.js',
  },
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: '[name].js',
    clean: true,
    libraryTarget: 'umd',
    globalObject: 'this',
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: [
          /node_modules/,
          path.resolve(__dirname, 'src/ui-helpers.js'), // Exclude ui-helpers.js from processing
        ],
        use: {
          loader: 'babel-loader',
          options: {
            presets: [
              ['@babel/preset-env', {
                targets: 'chrome >= 89',
                modules: 'commonjs',
                debug: true,
                useBuiltIns: 'usage',
                corejs: '3.38',
              }],
            ],
            plugins: ['@babel/plugin-transform-runtime'],
            sourceType: 'module',
            cacheDirectory: false,
          },
        },
      },
      {
        test: /\.mjs$/,
        include: /node_modules/,
        type: 'javascript/auto',
      },
    ],
  },
  resolve: {
    extensions: ['.js', '.json', '.mjs'],
    fallback: {
      crypto: require.resolve('crypto-browserify'),
      stream: require.resolve('stream-browserify'),
      buffer: require.resolve('buffer'),
      util: require.resolve('util'),
      url: require.resolve('url'),
      assert: require.resolve('assert'),
      process: require.resolve('process/browser'),
      path: require.resolve('path-browserify'),
      os: require.resolve('os-browserify/browser'),
      http: require.resolve('stream-http'),
      https: require.resolve('https-browserify'),
      fs: false,
      net: false,
      tls: false,
    },
    alias: {
      'process/browser': require.resolve('process/browser.js'),
      '@msgpack/msgpack': require.resolve('@msgpack/msgpack'),
    },
  },
  plugins: [
    new ProvidePlugin({
      Buffer: ['buffer', 'Buffer'],
      process: ['process/browser', 'default'],
    }),
    new CopyPlugin({
      patterns: [
        { from: 'manifest.json', to: 'manifest.json' },
        { from: 'src/*.html', to: '[name][ext]' },
        {
          from: 'src/*.js',
          to: '[name][ext]',
          globOptions: {
            ignore: [
              '**/gurftron.js', // Exclude gurftron.js to allow bundling
              '**/dashboard.js', // Exclude to avoid duplicating bundled files
              '**/background.js',
              '**/content.js',
            ],
          },
        },
        { from: 'src/*.css', to: '[name][ext]' },
        { from: 'src/images/*.svg', to: 'images/[name][ext]' },
        { from: 'src/images/*.jpg', to: 'images/[name][ext]' },
      ],
    }),
  ],
  mode: 'production',
  optimization: {
    minimize: true,
  },
  devtool: false,
  target: 'web',
};