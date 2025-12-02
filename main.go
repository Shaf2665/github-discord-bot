package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/bwmarrin/discordgo"
)

// ------------ GitHub payload structs ------------

type GitHubRepository struct {
	Name    string `json:"name"`
	HTMLURL string `json:"html_url"`
}

type GitHubPusher struct {
	Name string `json:"name"`
}

type GitHubCommit struct {
	ID        string `json:"id"`
	Message   string `json:"message"`
	URL       string `json:"url"`
	Timestamp string `json:"timestamp"`
	Author    struct {
		Name string `json:"name"`
	} `json:"author"`
}

type GitHubPushPayload struct {
	Ref        string          `json:"ref"`
	Repository GitHubRepository `json:"repository"`
	Pusher     GitHubPusher     `json:"pusher"`
	Commits    []GitHubCommit   `json:"commits"`
	HeadCommit GitHubCommit     `json:"head_commit"`
}

// ------------ Global vars ------------

var (
	discordToken   string
	channelID      string
	githubSecret   string
	discordSession *discordgo.Session
)

// ------------ Helpers ------------

func verifyGitHubSignature(r *http.Request, body []byte) bool {
	if githubSecret == "" {
		// No secret configured → skip verification
		return true
	}

	signature := r.Header.Get("X-Hub-Signature-256")
	if !strings.HasPrefix(signature, "sha256=") {
		return false
	}
	signature = strings.TrimPrefix(signature, "sha256=")

	mac := hmac.New(sha256.New, []byte(githubSecret))
	mac.Write(body)
	expectedMAC := mac.Sum(nil)
	expected := hex.EncodeToString(expectedMAC)

	return hmac.Equal([]byte(signature), []byte(expected))
}

func sendDiscordMessage(content string) error {
	_, err := discordSession.ChannelMessageSend(channelID, content)
	return err
}

// ------------ HTTP handler ------------

func githubWebhookHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	event := r.Header.Get("X-GitHub-Event")
	if event != "push" {
		// ignore non-push events
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ignored non-push event"))
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("error reading body:", err)
		http.Error(w, "cannot read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if !verifyGitHubSignature(r, body) {
		log.Println("invalid GitHub signature")
		http.Error(w, "invalid signature", http.StatusUnauthorized)
		return
	}

	var payload GitHubPushPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		log.Println("error parsing JSON:", err)
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if len(payload.Commits) == 0 {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("no commits"))
		return
	}

	branch := strings.TrimPrefix(payload.Ref, "refs/heads/")

	// Take the latest commit (head_commit)
	c := payload.HeadCommit
	if c.ID == "" {
		c = payload.Commits[len(payload.Commits)-1]
	}

	msg := fmt.Sprintf(
		"🔨 **New commit on `%s`**\n"+
			"📦 Repository: **%s**\n"+
			"🌿 Branch: `%s`\n"+
			"👤 Author: **%s**\n"+
			"📝 Message: %s\n"+
			"🔗 <%s>",
		payload.Repository.Name,
		payload.Repository.Name,
		branch,
		c.Author.Name,
		c.Message,
		c.URL,
	)

	if err := sendDiscordMessage(msg); err != nil {
		log.Println("error sending Discord message:", err)
		http.Error(w, "failed to send Discord message", http.StatusInternalServerError)
		return
	}

	log.Println("Posted commit to Discord:", c.ID)
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ok"))
}

// ------------ main ------------

func main() {
	discordToken = os.Getenv("DISCORD_TOKEN")
	channelID = os.Getenv("DISCORD_CHANNEL_ID")
	githubSecret = os.Getenv("GITHUB_WEBHOOK_SECRET") // optional

	if discordToken == "" || channelID == "" {
		log.Fatal("DISCORD_TOKEN and DISCORD_CHANNEL_ID must be set")
	}

	var err error
	discordSession, err = discordgo.New("Bot " + discordToken)
	if err != nil {
		log.Fatal("error creating Discord session:", err)
	}

	err = discordSession.Open()
	if err != nil {
		log.Fatal("error opening Discord session:", err)
	}
	defer discordSession.Close()

	http.HandleFunc("/github-webhook", githubWebhookHandler)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Println("Bot is running. HTTP webhook on port", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal("HTTP server failed:", err)
	}
}
