// Vulnerable: VUL-CVE-2020-27153
struct queue *ind_queue;	/* Queued ATT protocol indications */
	struct queue *write_queue;	/* Queue of PDUs ready to send */

	bt_att_timeout_func_t timeout_callback;
...
}

static void cancel_att_send_op(struct att_send_op *op)
{
	if (op->destroy)
		op->destroy(op->user_data);
...
	}

	op = queue_remove_if(att->req_queue, match_op_id, UINT_TO_PTR(id));
