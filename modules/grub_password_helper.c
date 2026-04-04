#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <gtk/gtk.h>

#define SALT_LEN   64
#define HASH_LEN   64
#define PASS_MAX 4096
#define ITERATIONS 10000

static void hex_upper(const unsigned char *buf, size_t len, char *out)
{
    static const char hex[] = "0123456789ABCDEF";
    for (size_t i = 0; i < len; i++) {
        out[i * 2]     = hex[buf[i] >> 4];
        out[i * 2 + 1] = hex[buf[i] & 0xf];
    }
    out[len * 2] = '\0';
}

typedef struct {
    GtkWidget *window;
    GtkWidget *entry1;
    GtkWidget *entry2;
    GtkWidget *err_label;
    char       pass[PASS_MAX];
    int        ok;
} DialogState;

static void on_cancel(GtkButton *btn, gpointer user_data)
{
    (void)btn;
    DialogState *s = user_data;
    gtk_window_destroy(GTK_WINDOW(s->window));
}

static void on_ok(GtkButton *btn, gpointer user_data)
{
    (void)btn;
    DialogState *s = user_data;

    const char *p1 = gtk_editable_get_text(GTK_EDITABLE(s->entry1));
    const char *p2 = gtk_editable_get_text(GTK_EDITABLE(s->entry2));

    if (!p1 || p1[0] == '\0') {
        gtk_label_set_text(GTK_LABEL(s->err_label), "Password cannot be empty.");
        return;
    }
    if (strcmp(p1, p2) != 0) {
        gtk_label_set_text(GTK_LABEL(s->err_label), "Passwords do not match.");
        gtk_editable_set_text(GTK_EDITABLE(s->entry2), "");
        return;
    }

    strncpy(s->pass, p1, PASS_MAX - 1);
    s->pass[PASS_MAX - 1] = '\0';
    s->ok = 1;

    gtk_editable_set_text(GTK_EDITABLE(s->entry1), "");
    gtk_editable_set_text(GTK_EDITABLE(s->entry2), "");
    gtk_window_destroy(GTK_WINDOW(s->window));
}

static void on_activate(GtkApplication *app, gpointer user_data)
{
    DialogState *s = user_data;

    s->window = gtk_window_new();
    gtk_window_set_title(GTK_WINDOW(s->window), "Set GRUB Boot Password");
    gtk_window_set_modal(GTK_WINDOW(s->window), TRUE);
    gtk_window_set_resizable(GTK_WINDOW(s->window), FALSE);
    gtk_window_set_application(GTK_WINDOW(s->window), app);

    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_start(box, 12);
    gtk_widget_set_margin_end(box, 12);
    gtk_widget_set_margin_top(box, 12);
    gtk_widget_set_margin_bottom(box, 12);
    gtk_window_set_child(GTK_WINDOW(s->window), box);

    GtkWidget *label = gtk_label_new(
        "Set a password for the GRUB boot menu.\n"
        "The default boot entry will start without a password.\n"
        "All other entries (recovery, GRUB shell, \xe2\x80\xa6) will require it."
    );
    gtk_label_set_wrap(GTK_LABEL(label), TRUE);
    gtk_box_append(GTK_BOX(box), label);

    s->entry1 = gtk_password_entry_new();
    gtk_password_entry_set_show_peek_icon(GTK_PASSWORD_ENTRY(s->entry1), TRUE);
    gtk_box_append(GTK_BOX(box), s->entry1);

    s->entry2 = gtk_password_entry_new();
    gtk_password_entry_set_show_peek_icon(GTK_PASSWORD_ENTRY(s->entry2), TRUE);
    gtk_box_append(GTK_BOX(box), s->entry2);

    s->err_label = gtk_label_new("");
    gtk_box_append(GTK_BOX(box), s->err_label);

    GtkWidget *btn_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_halign(btn_box, GTK_ALIGN_END);
    gtk_box_append(GTK_BOX(box), btn_box);

    GtkWidget *cancel_btn = gtk_button_new_with_label("Cancel");
    GtkWidget *ok_btn     = gtk_button_new_with_label("Set Password");
    gtk_box_append(GTK_BOX(btn_box), cancel_btn);
    gtk_box_append(GTK_BOX(btn_box), ok_btn);

    gtk_window_set_default_widget(GTK_WINDOW(s->window), ok_btn);

    g_signal_connect(cancel_btn, "clicked", G_CALLBACK(on_cancel), s);
    g_signal_connect(ok_btn,     "clicked", G_CALLBACK(on_ok),     s);
    g_signal_connect_swapped(s->entry2, "activate", G_CALLBACK(gtk_widget_activate_default), s->window);

    gtk_window_present(GTK_WINDOW(s->window));
}

int main(int argc, char *argv[])
{
    prctl(PR_SET_DUMPABLE, 0);

    DialogState s;
    explicit_bzero(&s, sizeof(s));

    GtkApplication *app = gtk_application_new(NULL, G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(app, "activate", G_CALLBACK(on_activate), &s);
    g_application_run(G_APPLICATION(app), argc, argv);
    g_object_unref(app);

    if (!s.ok) {
        explicit_bzero(&s, sizeof(s));
        return 2;
    }

    size_t plen = strlen(s.pass);

    unsigned char salt[SALT_LEN];
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        explicit_bzero(&s, sizeof(s));
        fprintf(stderr, "grub_password_helper: RAND_bytes failed\n");
        return 1;
    }

    unsigned char dk[HASH_LEN];
    if (PKCS5_PBKDF2_HMAC(s.pass, (int)plen,
                           salt, SALT_LEN,
                           ITERATIONS, EVP_sha512(),
                           HASH_LEN, dk) != 1) {
        explicit_bzero(&s, sizeof(s));
        fprintf(stderr, "grub_password_helper: PBKDF2 failed\n");
        return 1;
    }

    explicit_bzero(s.pass, PASS_MAX);

    char salt_hex[SALT_LEN * 2 + 1];
    char dk_hex[HASH_LEN * 2 + 1];
    hex_upper(salt, SALT_LEN, salt_hex);
    hex_upper(dk,   HASH_LEN, dk_hex);

    explicit_bzero(dk,   sizeof(dk));
    explicit_bzero(salt, sizeof(salt));

    printf("grub.pbkdf2.sha512.%d.%s.%s\n", ITERATIONS, salt_hex, dk_hex);

    explicit_bzero(salt_hex, sizeof(salt_hex));
    explicit_bzero(dk_hex,   sizeof(dk_hex));
    explicit_bzero(&s,       sizeof(s));
    return 0;
}
