#!/bin/sh
# WordPress reach lab -- idempotent installer. Runs once, exits, safe to re-run.
#
# Everything here exists to give the SWEEP something to reach. The lab's question is not "is there a
# bug" but "does Apolaki get to the parameters at all", so the goal is surface: query-string
# endpoints, real POST forms, an admin-ajax action namespace, a REST API, and two low-privilege
# accounts for the authorization matrix.
set -eu

WP="wp --path=/var/www/html --allow-root"
BASE="http://wpreach"

# ── wait for the DB and the webroot ──────────────────────────────────────────
i=0
while ! $WP core is-installed >/dev/null 2>&1; do
    if $WP core version >/dev/null 2>&1; then
        break                                   # core is present, just not installed yet
    fi
    i=$((i + 1))
    [ "$i" -gt 60 ] && echo "wordpress core never appeared in the shared volume" && exit 1
    sleep 2
done

if $WP core is-installed >/dev/null 2>&1; then
    echo "core already installed"
else
    $WP core install \
        --url="$BASE" \
        --title="Apolaki Reach Lab" \
        --admin_user=labadmin \
        --admin_password='LabAdmin!2026' \
        --admin_email=labadmin@wpreach.test \
        --skip-email
fi

# ── the two accounts the authorization matrix needs ──────────────────────────
# THE POINT OF THIS FILE. `run_session_lifecycle` reported "signup needs a manual step (captcha) --
# no sacrificial account can be minted" on every Shopify run, so the persona engine and the two-user
# BOLA matrix have never executed against a real application. Two SUBSCRIBERS, deliberately equal in
# privilege: a cross-user authorization test needs two peers, not a user and an admin. Anything
# alice can reach that belongs to bob is a finding; anything labadmin can reach is just being admin.
$WP user get alice >/dev/null 2>&1 || \
    $WP user create alice alice@wpreach.test --role=subscriber --user_pass='AlicePass!2026'
$WP user get bob >/dev/null 2>&1 || \
    $WP user create bob bob@wpreach.test --role=subscriber --user_pass='BobPass!2026'

# Registration left OPEN so the engine can mint its OWN sacrificial account rather than being handed
# credentials. A tool that only works with credentials someone typed for it has not been tested.
$WP option update users_can_register 1
$WP option update default_role subscriber

# ── surface ──────────────────────────────────────────────────────────────────
# Pretty permalinks OFF on purpose: `/?p=1`, `/?cat=2`, `/?s=x` are QUERY-STRING endpoints, which is
# exactly the shape `sweep_targets` selects on and the shape the Shopify surface did not offer.
$WP rewrite structure '' --hard >/dev/null 2>&1 || true

# Content, so the crawl has somewhere to go and the paginated/archive/search endpoints exist.
if [ "$($WP post list --post_type=post --format=count)" -lt 12 ]; then
    n=1
    while [ "$n" -le 12 ]; do
        $WP post create --post_type=post --post_status=publish \
            --post_title="Reach lab article $n" \
            --post_content="Article $n. <a href=\"/?p=1&amp;ref=nav&amp;lang=en\">related</a>" >/dev/null
        n=$((n + 1))
    done
fi
$WP post list --post_type=page --format=count | grep -q '^[1-9]' || \
    $WP post create --post_type=page --post_status=publish --post_title="Contact" \
        --post_content="Get in touch." >/dev/null

# Comments ON: a real POST form with several text fields, which is the input class `sweep_targets`
# was extended to cover (a page whose only injectable input is a form body).
$WP option update default_comment_status open
$WP option update comment_registration 0
$WP option update require_name_email 1

# ── plugins ──────────────────────────────────────────────────────────────────
# LATEST versions, from wordpress.org, installed for SURFACE not for known bugs. Each adds a
# different endpoint shape: admin-ajax actions, REST routes, front-end forms, shortcode-rendered
# query parameters. No version is pinned to a vulnerable release -- this lab measures reach, and a
# planted bug would tell us about the plant rather than about the crawl.
for p in contact-form-7 wordpress-seo wp-mail-smtp classic-editor akismet; do
    $WP plugin is-installed "$p" >/dev/null 2>&1 || $WP plugin install "$p" >/dev/null 2>&1 || \
        echo "could not install $p (offline?) -- continuing"
    $WP plugin activate "$p" >/dev/null 2>&1 || true
done

echo "---- reach lab ready ----"
echo "url         $BASE   (host: http://127.0.0.1:42101)"
echo "admin       labadmin / LabAdmin!2026"
echo "peers       alice / AlicePass!2026     bob / BobPass!2026"
echo "register    open, default role subscriber"
echo "posts       $($WP post list --post_type=post --format=count)"
echo "plugins     $($WP plugin list --status=active --format=count) active"
