
import { createClient } from '@supabase/supabase-js';
import dotenv from 'dotenv';

dotenv.config({ path: '.env' });

const supabaseUrl = process.env.VITE_SUPABASE_URL || process.env.SUPABASE_URL || '';
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.VITE_SUPABASE_ANON_KEY || '';
const supabase = createClient(supabaseUrl, supabaseKey);

async function check() {
    const { data: logs } = await supabase
        .from('email_logs')
        .select('id, recipient_email, email_purpose, status, error_message, created_at')
        .order('created_at', { ascending: false })
        .limit(20);

    if (logs) {
        logs.forEach(log => {
            console.log(`${log.created_at} | ${log.status} | ${log.recipient_email} | ${log.email_purpose}`);
            if (log.error_message) console.log(`  ERROR: ${log.error_message}`);
        });
    }
}

check();
