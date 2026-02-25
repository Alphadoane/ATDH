/** @type {import('tailwindcss').Config} */
export default {
    content: [
        "./index.html",
        "./src/**/*.{js,ts,jsx,tsx}",
    ],
    theme: {
        extend: {
            colors: {
                'cyber-bg': '#0a0a0c',
                'cyber-card': '#141417',
                'cyber-accent': '#00f2ff',
                'cyber-danger': '#ff003c',
                'cyber-warning': '#ffbd00',
                'cyber-success': '#00ff94',
            },
        },
    },
    plugins: [],
}
