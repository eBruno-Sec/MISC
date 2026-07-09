-- Re:Fit Database Schema
-- Run this in your Supabase SQL Editor

-- Core user accounts (user_id mirrors auth.uid())
CREATE TABLE users (
    user_id UUID PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    class_archetype VARCHAR(20) CHECK (class_archetype IN ('WARRIOR', 'ROGUE', 'MAGE')),
    current_level INT DEFAULT 1,
    current_exp INT DEFAULT 0,
    gacha_crystals INT DEFAULT 0,
    height_cm INT,
    weight_kg DECIMAL(5,1),
    age INT,
    gender VARCHAR(20),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- RPG attribute stats, one row per user
CREATE TABLE user_stats (
    user_id UUID PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    str_points INT DEFAULT 0,
    dex_points INT DEFAULT 0,
    agi_points INT DEFAULT 0,
    vit_points INT DEFAULT 0,
    int_points INT DEFAULT 0,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Workout session log
CREATE TABLE workout_quests (
    quest_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
    exercise_type VARCHAR(20) NOT NULL,
    duration_minutes INT NOT NULL,
    calories_burned INT DEFAULT 0,
    gacha_crystals_earned INT DEFAULT 0,
    completed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Summoned companions / harem gallery
CREATE TABLE unlocked_companions (
    companion_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
    companion_name VARCHAR(50) DEFAULT 'Summoned Heroine',
    workout_affinity VARCHAR(20) NOT NULL,
    image_storage_url TEXT NOT NULL,
    affinity_level INT DEFAULT 1,
    unlocked_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Row Level Security (each user sees only their own data)
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_stats ENABLE ROW LEVEL SECURITY;
ALTER TABLE workout_quests ENABLE ROW LEVEL SECURITY;
ALTER TABLE unlocked_companions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "users_own" ON users FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "stats_own" ON user_stats FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "quests_own" ON workout_quests FOR ALL USING (auth.uid() = user_id);
CREATE POLICY "companions_own" ON unlocked_companions FOR ALL USING (auth.uid() = user_id);
