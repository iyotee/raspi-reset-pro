#!/usr/bin/env bash
set -euo pipefail

############################################
# Raspberry Pi Professional Reset Utility
# Author: SwissLabs
# Version: 3.0
############################################

### CONSTANTS ###
readonly SCRIPT_VERSION="3.0"
readonly LOG_FILE="/var/log/rpi-reset.log"
readonly BACKUP_DIR="/backup/rpi-reset-$(date +%Y%m%d-%H%M%S)"
readonly LOCK_FILE="/var/run/rpi-reset.lock"
readonly CONFIG_FILE="/etc/rpi-reset.conf"
readonly STATE_FILE="/var/lib/rpi-reset/state.json"
readonly MIN_FREE_SPACE_GB=2

DRY_RUN=false
VERBOSE=false
FORCE_MODE=false

### COLORS ###
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly MAGENTA='\033[0;35m'
readonly NC='\033[0m'

############################################
# ERROR HANDLING
############################################

error_exit() {
  echo -e "${RED}❌ ERREUR: $1${NC}" >&2
  log "ERROR: $1"
  cleanup_and_exit 1
}

cleanup_and_exit() {
  local exit_code=${1:-0}
  rm -f "$LOCK_FILE" 2>/dev/null || true
  exit "$exit_code"
}

trap 'error_exit "Script interrompu"' INT TERM
trap 'cleanup_and_exit' EXIT

############################################
# PRE-CHECKS & VALIDATIONS
############################################

check_prerequisites() {
  # Root check
  [[ $EUID -ne 0 ]] && error_exit "Ce script doit être exécuté en root (sudo)"
  
  # Lock file check
  if [[ -f "$LOCK_FILE" ]]; then
    local lock_pid
    lock_pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
    if [[ -n "$lock_pid" ]] && kill -0 "$lock_pid" 2>/dev/null; then
      error_exit "Un reset est déjà en cours (PID: $lock_pid)"
    else
      log "Suppression d'un lock file obsolète"
      rm -f "$LOCK_FILE"
    fi
  fi
  
  echo $$ > "$LOCK_FILE"
  
  # Raspberry Pi check
  if ! grep -q "Raspberry Pi" /proc/cpuinfo 2>/dev/null && ! grep -q "BCM" /proc/cpuinfo 2>/dev/null; then
    log "ATTENTION: Ce système ne semble pas être un Raspberry Pi"
    confirm "Continuer quand même ?" || cleanup_and_exit 0
  fi
  
  # Disk space check
  local free_space_gb
  free_space_gb=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
  if [[ $free_space_gb -lt $MIN_FREE_SPACE_GB ]]; then
    error_exit "Espace disque insuffisant (${free_space_gb}GB < ${MIN_FREE_SPACE_GB}GB requis)"
  fi
  
  # Required commands check
  local required_cmds=(tar gzip apt systemctl journalctl)
  for cmd in "${required_cmds[@]}"; do
    command -v "$cmd" >/dev/null 2>&1 || error_exit "Commande requise non trouvée: $cmd"
  done
  
  # Create necessary directories
  mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$STATE_FILE")"
}

############################################
# LOGGING SYSTEM
############################################

log() {
  local level="${2:-INFO}"
  local message="$1"
  local timestamp
  timestamp=$(date '+%F %T')
  
  echo "[$timestamp] [$level] $message" | tee -a "$LOG_FILE"
  
  if [[ "$VERBOSE" == true ]]; then
    case "$level" in
      ERROR) echo -e "${RED}[$level] $message${NC}" ;;
      WARN)  echo -e "${YELLOW}[$level] $message${NC}" ;;
      SUCCESS) echo -e "${GREEN}[$level] $message${NC}" ;;
      INFO)  echo -e "${BLUE}[$level] $message${NC}" ;;
    esac
  fi
}

run() {
  local cmd="$*"
  
  if $DRY_RUN; then
    log "[DRY-RUN] $cmd" "INFO"
    return 0
  fi
  
  log "[EXEC] $cmd" "INFO"
  
  if $VERBOSE; then
    eval "$cmd" 2>&1 | tee -a "$LOG_FILE"
    local exit_code=${PIPESTATUS[0]}
  else
    eval "$cmd" >> "$LOG_FILE" 2>&1
    local exit_code=$?
  fi
  
  if [[ $exit_code -ne 0 ]]; then
    log "Commande échouée (code: $exit_code): $cmd" "ERROR"
    return $exit_code
  fi
  
  return 0
}

############################################
# CONFIRMATION SYSTEM
############################################

confirm() {
  if $FORCE_MODE; then
    log "Mode force activé: confirmation automatique" "WARN"
    return 0
  fi
  
  echo -e "${YELLOW}⚠️  $1${NC}"
  read -rp "Tapez 'YES' pour continuer (ou 'no' pour annuler): " ans
  
  case "${ans,,}" in
    yes) return 0 ;;
    no|n) 
      log "Opération annulée par l'utilisateur" "INFO"
      return 1
      ;;
    *)
      echo -e "${RED}Réponse invalide. Opération annulée.${NC}"
      return 1
      ;;
  esac
}

############################################
# STATE MANAGEMENT
############################################

save_state() {
  local operation="$1"
  local status="$2"
  local timestamp
  timestamp=$(date '+%s')
  
  mkdir -p "$(dirname "$STATE_FILE")"
  
  cat > "$STATE_FILE" <<EOF
{
  "operation": "$operation",
  "status": "$status",
  "timestamp": $timestamp,
  "date": "$(date -d @$timestamp '+%F %T')",
  "version": "$SCRIPT_VERSION"
}
EOF
}

get_last_operation() {
  if [[ -f "$STATE_FILE" ]]; then
    cat "$STATE_FILE"
  else
    echo "{}"
  fi
}

############################################
# BACKUP SYSTEM
############################################

backup_system() {
  confirm "📦 Voulez-vous sauvegarder /home, /etc, et les bases de données ?" || return
  
  log "=== DÉBUT DE LA SAUVEGARDE ===" "INFO"
  save_state "backup" "in_progress"
  
  mkdir -p "$BACKUP_DIR" || error_exit "Impossible de créer le répertoire de sauvegarde"
  
  # System info
  log "Sauvegarde des informations système" "INFO"
  {
    echo "=== System Information ==="
    echo "Date: $(date)"
    echo "Hostname: $(hostname)"
    echo "Kernel: $(uname -r)"
    echo "OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
    echo "Uptime: $(uptime -p)"
    dpkg -l > "$BACKUP_DIR/packages.list"
    systemctl list-units --state=enabled > "$BACKUP_DIR/services.list"
  } > "$BACKUP_DIR/system-info.txt"
  
  # Home directories
  if [[ -d /home ]]; then
    log "Sauvegarde de /home (peut prendre du temps...)" "INFO"
    run "tar czf '$BACKUP_DIR/home.tar.gz' -C / home --exclude='*.cache' --exclude='*/.npm' --exclude='*/.cargo' 2>/dev/null || true"
  fi
  
  # System configuration
  log "Sauvegarde de /etc" "INFO"
  run "tar czf '$BACKUP_DIR/etc.tar.gz' -C / etc"
  
  # Crontabs
  if [[ -d /var/spool/cron/crontabs ]]; then
    log "Sauvegarde des crontabs" "INFO"
    run "tar czf '$BACKUP_DIR/crontabs.tar.gz' -C / var/spool/cron/crontabs"
  fi
  
  # SSH keys
  if [[ -d /etc/ssh ]]; then
    log "Sauvegarde des clés SSH" "INFO"
    run "tar czf '$BACKUP_DIR/ssh-keys.tar.gz' -C / etc/ssh"
  fi
  
  # Network configuration
  if [[ -d /etc/NetworkManager ]] || [[ -d /etc/dhcpcd.conf ]]; then
    log "Sauvegarde de la configuration réseau" "INFO"
    run "tar czf '$BACKUP_DIR/network.tar.gz' -C / etc/network* etc/dhcpcd.conf etc/wpa_supplicant 2>/dev/null || true"
  fi
  
  # Create checksum
  log "Création des checksums" "INFO"
  (cd "$BACKUP_DIR" && sha256sum *.tar.gz > checksums.sha256)
  
  # Backup summary
  local backup_size
  backup_size=$(du -sh "$BACKUP_DIR" | cut -f1)
  
  log "Sauvegarde terminée avec succès" "SUCCESS"
  log "Emplacement: $BACKUP_DIR" "INFO"
  log "Taille: $backup_size" "INFO"
  
  save_state "backup" "completed"
  
  echo -e "${GREEN}✅ Sauvegarde créée: $BACKUP_DIR ($backup_size)${NC}"
}

############################################
# CACHE & LOG CLEANUP
############################################

clear_caches() {
  confirm "🧹 Nettoyer caches, logs et fichiers temporaires ?" || return
  
  log "=== NETTOYAGE DES CACHES ===" "INFO"
  save_state "clear_caches" "in_progress"
  
  # APT cache
  log "Nettoyage du cache APT" "INFO"
  run "apt clean"
  run "apt autoclean"
  
  # Journal logs
  log "Nettoyage des journaux système" "INFO"
  run "journalctl --rotate"
  run "journalctl --vacuum-time=7d"
  run "journalctl --vacuum-size=100M"
  
  # Old logs
  log "Nettoyage des anciens logs" "INFO"
  run "find /var/log -type f -name '*.log.*' -mtime +30 -delete"
  run "find /var/log -type f -name '*.gz' -mtime +30 -delete"
  
  # Temp files
  log "Nettoyage des fichiers temporaires" "INFO"
  run "find /tmp -type f -atime +7 -delete 2>/dev/null || true"
  run "find /var/tmp -type f -atime +7 -delete 2>/dev/null || true"
  
  # Thumbnail cache
  if [[ -d /home ]]; then
    log "Nettoyage des caches utilisateurs" "INFO"
    run "find /home -type d -name '.thumbnails' -exec rm -rf {} + 2>/dev/null || true"
    run "find /home -type d -name '.cache' -exec rm -rf {} + 2>/dev/null || true"
  fi
  
  # Package manager cache
  run "find /var/cache/apt/archives -type f -name '*.deb' -delete 2>/dev/null || true"
  
  local freed_space
  freed_space=$(df -h / | awk 'NR==2 {print $4}')
  
  log "Nettoyage terminé - Espace libre: $freed_space" "SUCCESS"
  save_state "clear_caches" "completed"
}

############################################
# USER MANAGEMENT
############################################

remove_users() {
  confirm "👤 Supprimer tous les utilisateurs non système (UID >= 1000) ?" || return
  
  log "=== SUPPRESSION DES UTILISATEURS ===" "INFO"
  save_state "remove_users" "in_progress"
  
  local excluded_users=("pi" "ubuntu" "root")
  local users_removed=0
  
  # List users to remove
  local users_to_remove=()
  while IFS=: read -r username _ uid _; do
    if [[ $uid -ge 1000 ]]; then
      local should_exclude=false
      for excluded in "${excluded_users[@]}"; do
        if [[ "$username" == "$excluded" ]]; then
          should_exclude=true
          break
        fi
      done
      
      if [[ "$should_exclude" == false ]]; then
        users_to_remove+=("$username")
      fi
    fi
  done < /etc/passwd
  
  if [[ ${#users_to_remove[@]} -eq 0 ]]; then
    log "Aucun utilisateur à supprimer" "INFO"
    return
  fi
  
  echo -e "${YELLOW}Utilisateurs qui seront supprimés:${NC}"
  printf '%s\n' "${users_to_remove[@]}"
  
  confirm "Confirmer la suppression de ${#users_to_remove[@]} utilisateur(s) ?" || return
  
  for username in "${users_to_remove[@]}"; do
    log "Suppression de l'utilisateur: $username" "INFO"
    
    # Kill user processes
    if run "pkill -u '$username' 2>/dev/null || true"; then
      sleep 2
    fi
    
    # Remove user
    if run "userdel -r '$username' 2>/dev/null"; then
      ((users_removed++))
      log "Utilisateur $username supprimé" "SUCCESS"
    else
      log "Échec de la suppression de $username" "WARN"
    fi
  done
  
  log "$users_removed utilisateur(s) supprimé(s)" "SUCCESS"
  save_state "remove_users" "completed"
}

############################################
# PACKAGE MANAGEMENT
############################################

purge_packages() {
  confirm "📦 Supprimer les paquets non essentiels et orphelins ?" || return
  
  log "=== NETTOYAGE DES PAQUETS ===" "INFO"
  save_state "purge_packages" "in_progress"
  
  # Autoremove
  log "Suppression des paquets orphelins" "INFO"
  run "apt autoremove --purge -y"
  
  # Optional: Remove specific packages
  local packages_to_remove=(
    "wolfram-engine"
    "libreoffice*"
    "scratch*"
    "minecraft-pi"
    "sonic-pi"
  )
  
  echo -e "${YELLOW}Paquets optionnels à supprimer:${NC}"
  printf '%s\n' "${packages_to_remove[@]}"
  
  if confirm "Supprimer ces paquets optionnels ?"; then
    for pkg in "${packages_to_remove[@]}"; do
      log "Tentative de suppression: $pkg" "INFO"
      run "apt purge $pkg -y 2>/dev/null || true"
    done
  fi
  
  # Clean residual configs
  log "Nettoyage des configurations résiduelles" "INFO"
  run "dpkg --list | grep '^rc' | awk '{print \$2}' | xargs dpkg --purge 2>/dev/null || true"
  
  log "Nettoyage des paquets terminé" "SUCCESS"
  save_state "purge_packages" "completed"
}

############################################
# CONFIGURATION RESET
############################################

reset_configs() {
  confirm "⚙️  Réinitialiser hostname, SSH, et configurations système ?" || return
  
  log "=== RESET DES CONFIGURATIONS ===" "INFO"
  save_state "reset_configs" "in_progress"
  
  # Hostname reset
  log "Réinitialisation du hostname" "INFO"
  run "echo raspberrypi > /etc/hostname"
  run "sed -i 's/127.0.1.1.*/127.0.1.1\traspberrypi/' /etc/hosts"
  
  # SSH keys regeneration
  if confirm "Régénérer les clés SSH du serveur ?"; then
    log "Régénération des clés SSH" "INFO"
    run "rm -f /etc/ssh/ssh_host_*"
    run "dpkg-reconfigure -f noninteractive openssh-server"
    run "systemctl restart ssh"
  fi
  
  # Network reset
  if confirm "Réinitialiser la configuration réseau ?"; then
    log "Réinitialisation du réseau" "INFO"
    run "rm -f /etc/network/interfaces.d/* 2>/dev/null || true"
    
    # Reset dhcpcd if exists
    if [[ -f /etc/dhcpcd.conf ]]; then
      run "cp /etc/dhcpcd.conf /etc/dhcpcd.conf.bak"
      run "apt install --reinstall dhcpcd5 -y"
    fi
  fi
  
  # Raspberry Pi specific configs
  if confirm "Réinstaller les paquets système Raspberry Pi ?"; then
    log "Réinstallation des paquets système" "INFO"
    run "apt install --reinstall raspberrypi-sys-mods -y 2>/dev/null || true"
    run "apt install --reinstall raspberrypi-ui-mods -y 2>/dev/null || true"
    run "apt install --reinstall raspi-config -y 2>/dev/null || true"
  fi
  
  # Machine ID regeneration
  if confirm "Régénérer le machine-id (important pour les clones) ?"; then
    log "Régénération du machine-id" "INFO"
    run "rm -f /etc/machine-id /var/lib/dbus/machine-id"
    run "systemd-machine-id-setup"
  fi
  
  log "Reset des configurations terminé" "SUCCESS"
  save_state "reset_configs" "completed"
}

############################################
# NETWORK RESET
############################################

reset_network() {
  confirm "🌐 Réinitialiser complètement la configuration réseau ?" || return
  
  log "=== RESET RÉSEAU COMPLET ===" "INFO"
  save_state "reset_network" "in_progress"
  
  # WiFi credentials
  if [[ -f /etc/wpa_supplicant/wpa_supplicant.conf ]]; then
    log "Suppression des réseaux WiFi enregistrés" "INFO"
    run "rm -f /etc/wpa_supplicant/wpa_supplicant.conf"
    run "touch /etc/wpa_supplicant/wpa_supplicant.conf"
  fi
  
  # NetworkManager connections
  if [[ -d /etc/NetworkManager/system-connections ]]; then
    log "Suppression des connexions NetworkManager" "INFO"
    run "rm -f /etc/NetworkManager/system-connections/*"
  fi
  
  # Reset firewall rules
  if command -v ufw >/dev/null 2>&1; then
    log "Réinitialisation du pare-feu" "INFO"
    run "ufw --force reset"
  fi
  
  # Clear ARP cache
  run "ip -s -s neigh flush all 2>/dev/null || true"
  
  log "Reset réseau terminé" "SUCCESS"
  save_state "reset_network" "completed"
}

############################################
# SECURITY HARDENING
############################################

security_audit() {
  log "=== AUDIT DE SÉCURITÉ ===" "INFO"
  
  echo -e "${CYAN}Vérifications de sécurité:${NC}"
  
  # Check default passwords
  echo -n "- Mot de passe par défaut pour 'pi': "
  if grep -q '^\$6\$' /etc/shadow | grep pi; then
    echo -e "${GREEN}OK (changé)${NC}"
  else
    echo -e "${RED}ATTENTION: Mot de passe potentiellement par défaut${NC}"
  fi
  
  # Check SSH root login
  echo -n "- Connexion SSH root: "
  if grep -q "^PermitRootLogin no" /etc/ssh/sshd_config; then
    echo -e "${GREEN}Désactivé (recommandé)${NC}"
  else
    echo -e "${YELLOW}Activé (non recommandé)${NC}"
  fi
  
  # Check firewall
  echo -n "- Pare-feu: "
  if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    echo -e "${GREEN}Actif${NC}"
  else
    echo -e "${YELLOW}Inactif${NC}"
  fi
  
  # Check updates
  echo -n "- Mises à jour système: "
  local updates
  updates=$(apt list --upgradable 2>/dev/null | grep -c upgradable || echo "0")
  if [[ $updates -eq 0 ]]; then
    echo -e "${GREEN}À jour${NC}"
  else
    echo -e "${YELLOW}$updates mise(s) à jour disponible(s)${NC}"
  fi
}

############################################
# FULL SYSTEM RESET
############################################

full_reset() {
  echo -e "${RED}"
  echo "╔═══════════════════════════════════════════════════════╗"
  echo "║           ⚠️  RESET COMPLET DU SYSTÈME  ⚠️           ║"
  echo "║                                                       ║"
  echo "║  Cette opération est IRRÉVERSIBLE et comprend:       ║"
  echo "║  • Sauvegarde système complète                       ║"
  echo "║  • Suppression de tous les utilisateurs              ║"
  echo "║  • Purge des paquets non essentiels                  ║"
  echo "║  • Reset des configurations système                  ║"
  echo "║  • Nettoyage complet des caches                      ║"
  echo "║  • Régénération des clés SSH                         ║"
  echo "║  • Redémarrage automatique                           ║"
  echo "╚═══════════════════════════════════════════════════════╝"
  echo -e "${NC}"
  
  confirm "🔥 Êtes-vous ABSOLUMENT sûr de vouloir continuer ?" || return
  confirm "🔥🔥 Dernière confirmation - Cette action est IRRÉVERSIBLE" || return
  
  log "=== DÉBUT DU RESET COMPLET ===" "INFO"
  save_state "full_reset" "in_progress"
  
  # Execute all reset operations
  backup_system
  remove_users
  purge_packages
  reset_configs
  reset_network
  clear_caches
  
  log "RESET COMPLET TERMINÉ AVEC SUCCÈS" "SUCCESS"
  save_state "full_reset" "completed"
  
  echo -e "${GREEN}"
  echo "╔═══════════════════════════════════════════════════════╗"
  echo "║              ✅ RESET TERMINÉ AVEC SUCCÈS             ║"
  echo "║                                                       ║"
  echo "║  Le système va redémarrer dans 10 secondes...        ║"
  echo "║  Sauvegarde disponible: $BACKUP_DIR"
  echo "╚═══════════════════════════════════════════════════════╝"
  echo -e "${NC}"
  
  sleep 10
  run "reboot"
}

############################################
# SYSTEM INFORMATION
############################################

show_system_info() {
  clear
  echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
  echo -e "${CYAN}║          📊 INFORMATIONS SYSTÈME                      ║${NC}"
  echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"
  echo
  
  echo -e "${BLUE}Système:${NC}"
  echo "  Hostname: $(hostname)"
  echo "  OS: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
  echo "  Kernel: $(uname -r)"
  echo "  Uptime: $(uptime -p)"
  echo
  
  echo -e "${BLUE}Stockage:${NC}"
  df -h / | tail -n1 | awk '{print "  Utilisé: "$3"/"$2" ("$5")"}'
  df -h / | tail -n1 | awk '{print "  Disponible: "$4}'
  echo
  
  echo -e "${BLUE}Mémoire:${NC}"
  free -h | grep Mem | awk '{print "  Utilisée: "$3"/"$2}'
  free -h | grep Mem | awk '{print "  Disponible: "$7}'
  echo
  
  echo -e "${BLUE}Utilisateurs (UID >= 1000):${NC}"
  awk -F: '$3 >= 1000 {print "  - "$1" (UID: "$3")"}' /etc/passwd
  echo
  
  echo -e "${BLUE}Services actifs:${NC}"
  systemctl list-units --type=service --state=running --no-pager | grep -c "loaded active running" | awk '{print "  "$1" service(s) en cours d'\''exécution"}'
  echo
  
  echo -e "${BLUE}Dernière opération:${NC}"
  if [[ -f "$STATE_FILE" ]]; then
    local last_op
    last_op=$(jq -r '.operation' "$STATE_FILE" 2>/dev/null || echo "N/A")
    local last_status
    last_status=$(jq -r '.status' "$STATE_FILE" 2>/dev/null || echo "N/A")
    local last_date
    last_date=$(jq -r '.date' "$STATE_FILE" 2>/dev/null || echo "N/A")
    echo "  Type: $last_op"
    echo "  Statut: $last_status"
    echo "  Date: $last_date"
  else
    echo "  Aucune opération enregistrée"
  fi
  echo
}

############################################
# MENU SYSTEM
############################################

menu() {
  clear
  echo -e "${GREEN}╔═══════════════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}║      🔧 Raspberry Pi Advanced Reset Utility v$SCRIPT_VERSION     ║${NC}"
  echo -e "${GREEN}╚═══════════════════════════════════════════════════════╝${NC}"
  echo
  echo -e "${BLUE}Opérations de sauvegarde:${NC}"
  echo "  1) 📦 Sauvegarde système complète"
  echo
  echo -e "${BLUE}Opérations de nettoyage:${NC}"
  echo "  2) 🧹 Nettoyer caches & logs"
  echo "  3) 📦 Purger paquets non essentiels"
  echo
  echo -e "${BLUE}Opérations de reset:${NC}"
  echo "  4) 👤 Supprimer utilisateurs non système"
  echo "  5) ⚙️  Reset configurations système"
  echo "  6) 🌐 Reset configuration réseau"
  echo
  echo -e "${BLUE}Opérations avancées:${NC}"
  echo "  7) 🔥 RESET COMPLET (IRRÉVERSIBLE)"
  echo "  8) 🔒 Audit de sécurité"
  echo "  9) 📊 Informations système"
  echo
  echo -e "${BLUE}Options:${NC}"
  echo "  d) $(if $DRY_RUN; then echo -e "${GREEN}✓${NC}"; else echo " "; fi) Dry-Run (simulation)"
  echo "  v) $(if $VERBOSE; then echo -e "${GREEN}✓${NC}"; else echo " "; fi) Mode verbeux"
  echo "  f) $(if $FORCE_MODE; then echo -e "${YELLOW}✓${NC}"; else echo " "; fi) Mode force (sans confirmation)"
  echo
  echo "  0) ❌ Quitter"
  echo
  read -rp "Votre choix: " choice

  case $choice in
    1) backup_system ;;
    2) clear_caches ;;
    3) purge_packages ;;
    4) remove_users ;;
    5) reset_configs ;;
    6) reset_network ;;
    7) full_reset ;;
    8) security_audit ;;
    9) show_system_info ;;
    d|D) DRY_RUN=!$DRY_RUN; log "Dry-run: $DRY_RUN" "INFO" ;;
    v|V) VERBOSE=!$VERBOSE; log "Verbose: $VERBOSE" "INFO" ;;
    f|F) 
      FORCE_MODE=!$FORCE_MODE
      log "Mode force: $FORCE_MODE" "WARN"
      if $FORCE_MODE; then
        echo -e "${RED}⚠️  ATTENTION: Les confirmations sont désactivées${NC}"
      fi
      ;;
    0) 
      log "Script terminé par l'utilisateur" "INFO"
      echo -e "${GREEN}Au revoir!${NC}"
      cleanup_and_exit 0
      ;;
    *) 
      echo -e "${RED}❌ Choix invalide${NC}"
      sleep 1
      ;;
  esac
}

############################################
# MAIN EXECUTION
############################################

main() {
  clear
  echo -e "${CYAN}Initialisation...${NC}"
  
  # Run pre-checks
  check_prerequisites
  
  log "Script démarré (version $SCRIPT_VERSION)" "INFO"
  log "Mode dry-run: $DRY_RUN | Mode verbeux: $VERBOSE | Mode force: $FORCE_MODE" "INFO"
  
  # Main loop
  while true; do
    menu
    echo
    read -rp "Appuyez sur Entrée pour continuer..."