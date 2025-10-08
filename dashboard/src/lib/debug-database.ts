// Debug utility for testing database connection
import { databaseClient } from './database';

export async function debugDatabaseConnection() {
    console.log('=== Database Connection Debug ===');

    // Check if we have an auth token
    const token = localStorage.getItem('accessToken');
    console.log('Auth token exists:', !!token);
    console.log('Token preview:', token ? token.substring(0, 20) + '...' : 'No token');

    // Test simple SQL query
    try {
        console.log('\n1. Testing simple SQL query...');
        const result = await databaseClient.executeSQL('SELECT 1 as test');
        console.log('✅ Simple query success:', result);
    } catch (error) {
        console.error('❌ Simple query failed:', error);
    }

    // Test getting schemas
    try {
        console.log('\n2. Testing schema retrieval...');
        const schemas = await databaseClient.getSchemas();
        console.log('✅ Schemas retrieved:', schemas);
    } catch (error) {
        console.error('❌ Schema retrieval failed:', error);
    }

    // Test getting tables
    try {
        console.log('\n3. Testing table retrieval...');
        const tables = await databaseClient.getTables('public');
        console.log('✅ Tables retrieved:', tables.length, 'tables');
    } catch (error) {
        console.error('❌ Table retrieval failed:', error);
    }
}

// Test without authentication
export async function testWithoutAuth() {
    console.log('\n=== Testing without authentication ===');

    // Temporarily remove token
    const originalToken = localStorage.getItem('accessToken');
    localStorage.removeItem('accessToken');

    try {
        const result = await databaseClient.executeSQL('SELECT 1 as test');
        console.log('✅ Query without auth succeeded:', result);
    } catch (error) {
        console.error('❌ Query without auth failed:', error);
    }

    // Restore token
    if (originalToken) {
        localStorage.setItem('accessToken', originalToken);
    }
}

// Call this from browser console: debugDatabaseConnection()
(window as any).debugDatabaseConnection = debugDatabaseConnection;
(window as any).testWithoutAuth = testWithoutAuth;