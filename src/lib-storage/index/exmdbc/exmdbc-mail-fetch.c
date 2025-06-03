#include <stdio.h>
#include "lib.h"
#include "str.h"
#include "ioloop.h"
#include "istream.h"

#include "exmdbc-mail.h"
#include "exmdbc-storage.h"
#include "exmdbc-mailbox.h"
#include "exmdb_client_c.h"

void exmdbc_mail_fetch_flush(struct exmdbc_mailbox *mbox)
{
    fprintf(stdout, "[EXMDBC] exmdbc_mail_fetch_flush called (dummy)\n");
    // TODO: Actually trigger a FETCH operation via exmdb_client
}

static int exmdbc_mail_send_fetch(struct mail *_mail, enum mail_fetch_field fields, const char *const *headers)
{
    fprintf(stdout, "[EXMDBC] exmdbc_mail_send_fetch called (dummy)\n");

    struct exmdbc_mail *mail = EXMDBC_MAIL(_mail);
    struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(_mail->box);

    // TODO: Build actual FETCH command and call exmdbc_client_get_message_properties

    mail->fetching_fields |= fields;
    mail->fetch_count++;
    mail->fetch_sent = TRUE;
    mail->fetch_failed = FALSE;

    return 1;
}

// Used internally to check what fields are still missing
static bool exmdbc_mail_have_fields(struct exmdbc_mail *mail, enum mail_fetch_field fields)
{
    fprintf(stdout, "[EXMDBC] exmdbc_mail_have_fields called (dummy)\n");

    // TODO: Implement proper field tracking
    return TRUE;
}

static enum mail_fetch_field exmdbc_mail_get_wanted_fetch_fields(struct exmdbc_mail *mail)
{
    fprintf(stdout, "[EXMDBC] exmdbc_mail_get_wanted_fetch_fields called (dummy)\n");

    // TODO: Determine fields needed based on index cache or settings
    return 0;
}

// This is the main entry point for FETCH
int exmdbc_mail_fetch(struct mail *_mail, enum mail_fetch_field fields, const char *const *headers)
{
    fprintf(stdout, "[EXMDBC] exmdbc_mail_fetch called\n");

    struct exmdbc_mail *mail = EXMDBC_MAIL(_mail);
    struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(_mail->box);

    if (_mail->saving) {
        mail_storage_set_error(_mail->box->storage, MAIL_ERROR_NOTPOSSIBLE, "Can't FETCH uncommitted mail");
        return -1;
    }

    fields |= exmdbc_mail_get_wanted_fetch_fields(mail);

    int ret = 0;
    T_BEGIN {
        ret = exmdbc_mail_send_fetch(_mail, fields, headers);
    } T_END;

    if (ret < 0)
        return -1;

    if (ret > 0)
        exmdbc_mail_fetch_flush(mbox);

    while (mail->fetch_count > 0 &&
           (!exmdbc_mail_have_fields(mail, fields) || !mail->header_list_fetched)) {
        // TODO: Actually process async events
        exmdbc_mailbox_run_nofetch(mbox);
    }

    if (mail->fetch_failed) {
        mail_storage_set_internal_error(&mbox->storage->storage);
        return -1;
    }
    return 0;
}

bool exmdbc_mail_prefetch(struct mail *_mail)
{
    fprintf(stdout, "[EXMDBC] exmdbc_mail_prefetch called (dummy)\n");

    struct exmdbc_mail *mail = EXMDBC_MAIL(_mail);
    return !mail->imail.data.prefetch_sent;
}

// Stream init (currently dummy)
void exmdbc_mail_init_stream(struct exmdbc_mail *mail)
{
    fprintf(stdout, "[EXMDBC] exmdbc_mail_init_stream called (dummy)\n");

    struct index_mail *imail = &mail->imail;
    struct mail *_mail = &imail->mail.mail;

    // TODO: Set stream from actual data
    i_stream_set_name(imail->data.stream,
        t_strdup_printf("exmdbc mail uid=%u", _mail->uid));
    index_mail_set_read_buffer_size(_mail, imail->data.stream);
}

// Dummy
void exmdbc_mail_try_init_stream_from_cache(struct exmdbc_mail *mail)
{
    fprintf(stdout, "[EXMDBC] exmdbc_mail_try_init_stream_from_cache called\n");

    struct mail *_mail = &mail->imail.mail.mail;
    struct exmdbc_mailbox *mbox = EXMDBC_MAILBOX(_mail->box);

    if (mbox->prev_mail_cache.uid == _mail->uid)
        ; // TODO: Implement if caching used
}

// Dummy update logic
void exmdbc_mail_fetch_update(struct exmdbc_mail *mail,
                              const struct exmdbc_untagged_reply *reply,
                              const struct exmdbc_arg *args)
{
    fprintf(stdout, "[EXMDBC] exmdbc_mail_fetch_update called (dummy)\n");
    // TODO: Parse Gromox fetch result into internal state
}
