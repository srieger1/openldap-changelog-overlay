/*
 * Copyright 2010 by Sebastian Rieger
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */
/* ACKNOWLEDGEMENTS
 * This work was initially developed by Neil Dunbar.
 * Thanks to Paul Turgyan for patching some leftover memory leaks.
 */

#include "portable.h"

#ifdef SLAPD_OVER_CHANGELOG

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "config.h"
#include "lutil.h"
#include "ldif.h"
#include "ldap_rq.h"

static slap_overinst changelog;

static slap_callback nullsc = { NULL, NULL, NULL, NULL };

typedef struct _cb_data_st 
{
#ifdef HAVE_LONG_LONG
    unsigned long long largest;
#else
    unsigned long largest;
#endif /* HAVE_LONG_LONG */
    BerVarray ba;
    AttributeDescription *si_ad_changeNumber;
} cb_data_st;
    
typedef struct _entry_st 
{
    unsigned long es_id;
    unsigned long es_connid;
    Entry *es_e;
    struct _entry_st *es_next;
} changelog_entry;

typedef struct _filter_st 
{
    LDAPURLDesc *lud;
    Filter *filt;
    struct _filter_st *f_next;
} filter_st;
    
typedef struct changelog_data {
    const char *message;
    BackendDB *backend;
    struct berval backend_suffix;
    changelog_entry *esave;
    int deladd;
    time_t prune; /* minimum interval for pruning the changelog */
    time_t lastprune; /* last time we pruned the changelog */
    time_t retain; /* retain changelog records for this many seconds */

    struct re_s *task;

#ifdef HAVE_LONG_LONG
    unsigned long long first_change_num;
    unsigned long long last_change_num;
#else
    unsigned long first_change_num;
    unsigned long last_change_num;
#endif
    int got_change_numbers;
    filter_st *filters;
    
    AttributeDescription *si_ad_firstChangeNumber;
    AttributeDescription *si_ad_lastChangeNumber;
    AttributeDescription *si_ad_changeNumber;
    AttributeDescription *si_ad_changeCSN;
    AttributeDescription *si_ad_changeType;
    AttributeDescription *si_ad_changes;
    AttributeDescription *si_ad_targetDN;
    AttributeDescription *si_ad_changedAttribute;
    AttributeDescription *si_ad_oldEntry;
    AttributeDescription *si_ad_deleteOldRDN;
    AttributeDescription *si_ad_newRDN;
    AttributeDescription *si_ad_newSuperior;

} changelog_data;

static int add_changelog_entry( Operation *op, Backend *be );
static void * prune_changelog( void *ctx, void *arg );
static void get_change_numbers( Operation *op, Backend *be,
                                changelog_data *id );
static void commit_change_numbers( Operation *op,
                                   Backend *be, changelog_data *id );

static ldap_pvt_thread_mutex_t changelog_mutex;
static ldap_pvt_thread_mutex_t changenum_mutex;

static ConfigDriver clog_cf_gen;

enum {
	CLOG_DB = 1,
	CLOG_CONVREPLACE,
	CLOG_RETENTION,
	CLOG_PRUNE,
	CLOG_DUMPFILTER
};

static ConfigTable clog_cf_attrs[] = {
	{ "changelog_db", "suffix", 2, 2, 0, ARG_DN|ARG_MAGIC|CLOG_DB,
		clog_cf_gen, "( OLcfgOvAt:24.1 NAME 'olcChangelogDB' "
			"DESC 'DB where changes will be stored' "
			"SUP distinguishedName SINGLE-VALUE )", NULL, NULL },
	{ "changelog_convert_replace", NULL, 2, 0, 0,
		ARG_MAGIC|ARG_ON_OFF|CLOG_CONVREPLACE,
		clog_cf_gen, "( OLcfgOvAt:24.2 NAME 'olcChangelogConvReplace' "
			"DESC 'Flag to toggle conversion of replace operations' "
			"SYNTAX OMsBoolean SINGLE-VALUE )", NULL, NULL },
	{ "changelog_retention_time", "seconds", 2, 2, 0, ARG_INT|ARG_MAGIC|CLOG_RETENTION,
		clog_cf_gen, "( OLcfgOvAt:24.3 NAME 'olcChangelogRetention' "
			"DESC 'Maximum age for storing entries in the changelog' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "changelog_prune_time", "seconds", 2, 2, 0, ARG_INT|ARG_MAGIC|CLOG_PRUNE,
		clog_cf_gen, "( OLcfgOvAt:24.4 NAME 'olcChangelogPrune' "
			"DESC 'Changelog cleanup parameters' "
			"SYNTAX OMsInteger SINGLE-VALUE )", NULL, NULL },
	{ "changelog_dump_entry_filter", "filter URI", 2, 2, 0, ARG_MAGIC|CLOG_DUMPFILTER,
		clog_cf_gen, "( OLcfgOvAt:24.5 NAME 'olcChangelogDumpFilter' "
			"DESC 'Log entries on modify/delete that match the filter URI' "
			"SYNTAX OMsDirectoryString SINGLE-VALUE )", NULL, NULL },
	{ NULL, NULL, 0, 0, 0, ARG_IGNORED }
};

static ConfigOCs clog_cf_ocs[] = {
	{ "( OLcfgOvOc:24.1 "
		"NAME 'olcChangelogConfig' "
		"DESC 'Changelog configuration' "
		"SUP olcOverlayConfig "
		"MAY ( olcChangelogDB $ olcChangelogConvReplace $ olcChangelogRetention $ "
			"olcChangelogPrune $ olcChangelogDumpFilter ) )",
			Cft_Overlay, clog_cf_attrs },
	{ NULL , 0, NULL}
};

#define CLOG_SCHEMA_ROOT	"2.16.840.1.113730.3"
#define CLOG_SCHEMA_ROOT_OVL "1.3.6.1.4.1.11.4.2"

#define CLOG_SCHEMA_AT CLOG_SCHEMA_ROOT ".1"
#define CLOG_SCHEMA_OC CLOG_SCHEMA_ROOT ".2"
#define CLOG_SCHEMA_AT_OVL CLOG_SCHEMA_ROOT_OVL ".1"
#define CLOG_SCHEMA_OC_OVL CLOG_SCHEMA_ROOT_OVL ".2"

static AttributeDescription *ad_changeNumber, *ad_targetDN, *ad_changeType, *ad_changes,
	*ad_newRDN, *ad_deleteOldRDN, *ad_newSuperior, *ad_changeCSN, *ad_changelog,
	*ad_changedAttribute, *ad_firstChangeNumber, *ad_lastChangeNumber, *ad_oldEntry;

static struct {
	char *at;
	AttributeDescription **ad;
} clattrs[] = {
	{ "( " CLOG_SCHEMA_AT ".5 NAME 'changeNumber' "
		"DESC 'a number which uniquely identifies a change made to a directory entry' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
		"EQUALITY integerMatch "
		"ORDERING integerOrderingMatch "
		"SINGLE-VALUE )", &ad_changeNumber },
	{ "( " CLOG_SCHEMA_AT ".6 NAME 'targetDN' "
		"DESC 'the DN of the entry which was modified' "
		"EQUALITY distinguishedNameMatch "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 "
		"SINGLE-VALUE )", &ad_targetDN },
	{ "( " CLOG_SCHEMA_AT ".7 NAME 'changeType' "
		"DESC 'the type of change made to an entry' "
		"EQUALITY caseIgnoreMatch "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
		"SINGLE-VALUE )", &ad_changeType },
	{ "( " CLOG_SCHEMA_AT ".8 NAME 'changes' "
		"DESC 'a set of changes to apply to an entry' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )", &ad_changes },
	{ "( " CLOG_SCHEMA_AT ".9 NAME 'newRDN' "
		"DESC 'the new RDN of an entry which is the target of a modrdn operation' "
		"EQUALITY distinguishedNameMatch "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 "
		"SINGLE-VALUE )", &ad_newRDN },
	{ "( " CLOG_SCHEMA_AT ".10 NAME 'deleteOldRDN' "
		"DESC 'a flag which indicates if the old RDN should be retained as an attribute of the entry' "
		"EQUALITY booleanMatch "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 "
		"SINGLE-VALUE )", &ad_deleteOldRDN },
	{ "( " CLOG_SCHEMA_AT ".11 NAME 'newSuperior' "
		"DESC 'the new parent of an entry which is the target of a moddn operation' "
		"EQUALITY distinguishedNameMatch "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 "
		"SINGLE-VALUE )", &ad_newSuperior },
	{ "( " CLOG_SCHEMA_AT ".12 NAME 'changeCSN' "
		"DESC 'change sequence number of the entry content' "
		"EQUALITY octetStringMatch "
		"ORDERING octetStringOrderingMatch "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.40{64} "
		"SINGLE-VALUE )", &ad_changeCSN },
	{ "( " CLOG_SCHEMA_AT ".35 NAME 'changelog' "
		"DESC 'the distinguished name of the entry which contains the set of entries comprising this servers changelog' "
		"EQUALITY distinguishedNameMatch "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )", &ad_changelog },
	{ "( " CLOG_SCHEMA_AT_OVL ".113 NAME 'changedAttribute' "
		"DESC 'attributes changed in the entry content' "
                "EQUALITY caseIgnoreMatch " 
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )", &ad_changedAttribute },
	{ "( " CLOG_SCHEMA_AT_OVL ".114 NAME 'firstChangeNumber' "
		"DESC 'first change number in changelog' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
		"EQUALITY integerMatch "
		"ORDERING integerOrderingMatch "
		"SINGLE-VALUE )", &ad_firstChangeNumber },
	{ "( " CLOG_SCHEMA_AT_OVL ".115 NAME 'lastChangeNumber' "
		"DESC 'last change number in changelog' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
		"EQUALITY integerMatch "
		"ORDERING integerOrderingMatch "
		"SINGLE-VALUE )", &ad_lastChangeNumber },
	{ "( " CLOG_SCHEMA_AT_OVL ".116 NAME 'oldEntry' "
		"DESC 'copy of deleted or modified entry' "
		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )", &ad_oldEntry },
	{ NULL, NULL }
};

static ObjectClass *clog_entry, *clog_container;

static struct {
	char *ot;
	ObjectClass **oc;
} clocs[] = {
	{ "( " CLOG_SCHEMA_OC ".1 NAME 'changeLogEntry' "
		"DESC 'Entry to represent changes made in the directory' "
		"SUP top STRUCTURAL "
		"MUST ( changeNumber $ targetDN $ changeType ) "
		"MAY ( changeCSN $ changes $ newRDN $ deleteOldRDN $ newSuperior $ changedAttribute $ oldEntry ) )", &clog_entry },
	{ "( " CLOG_SCHEMA_OC_OVL ".21 NAME 'changeLog' "
		"DESC 'Root Entry to store the changelog' "
		"SUP top STRUCTURAL "
		"MUST ( firstChangeNumber $ lastChangeNumber ) "
		"MAY ( cn $ description ) )",	&clog_container },
	{ NULL, NULL }
};


static int
clog_cf_gen(ConfigArgs *c)
{
        slap_overinst *on = (slap_overinst *)c->bi;
        changelog_data *id = (changelog_data *)on->on_bi.bi_private;
        struct berval agebv, bv, pv;
        filter_st *freefs, *prevfs;

        Filter *f;
        LDAPURLDesc *lud = NULL;

        int rc = 0;

	switch( c->op ) {
	case SLAP_CONFIG_EMIT:
		switch( c->type ) {
		case CLOG_DB:
		        if ( !BER_BVISEMPTY( &id->backend_suffix )) {
                            value_add_one( &c->rvalue_vals, &id->backend_suffix );
                            value_add_one( &c->rvalue_nvals, &id->backend_suffix );
                        }
		        else if (id->backend) {
			    value_add( &c->rvalue_vals, id->backend->be_suffix );
                            value_add( &c->rvalue_nvals, id->backend->be_nsuffix );
                        } else {
                            snprintf( c->cr_msg, sizeof( c->cr_msg ),
                                    "changelog: \"changelog_db <suffix>\" must be specified" );
                            Debug( LDAP_DEBUG_ANY, "%s: %s \"%s\"\n",
                                    c->log, c->cr_msg, c->value_dn.bv_val );
                            rc = 1;
                            break;
                        }
			break;

		case CLOG_CONVREPLACE:
			if ( id->deladd )
				c->value_int = id->deladd;
			else
				rc = 1;
			break;

		case CLOG_RETENTION:
			c->value_int = id->retain;
			break;

		case CLOG_PRUNE:
			c->value_int = id->prune;
			break;

		case CLOG_DUMPFILTER:
			if ( id->filters ) {

			    prevfs = NULL;
			    freefs = id->filters;

          		    do
			    {
                                filter2bv( id->filters->filt, &agebv );
                                value_add_one( &c->rvalue_vals, &agebv );
                                
                                ber_memfree(agebv.bv_val);
                                
                                prevfs = freefs;
                                freefs = freefs->f_next;
                            } while (prevfs->f_next);

                        } else {
                            rc = 1;
                        }
			break;
		}
		break;

	case LDAP_MOD_DELETE:
		switch( c->type ) {
		case CLOG_DB:
			/* noop. this should always be a valid backend. */
			break;
		case CLOG_CONVREPLACE:
		        id->deladd = 0;
			break;
		case CLOG_RETENTION:
		        id->retain = 0;
			break;
		case CLOG_PRUNE:
		        if ( id->task ) {
		                struct re_s *re = id->task;
		                id->task = NULL;
		                if ( ldap_pvt_runqueue_isrunning( &slapd_rq, re ))
		                        ldap_pvt_runqueue_stoptask( &slapd_rq, re );
                                ldap_pvt_runqueue_remove( &slapd_rq, re );
                        }
			id->prune = 0;
			break;
		case CLOG_DUMPFILTER:

		        prevfs = NULL;

                        freefs = id->filters;
		        
		        do
		        {
		            if (prevfs) {
		                prevfs->f_next = NULL; 
		                prevfs = NULL;
                            }
		            
		            if ( freefs->filt) {
		              filter_free( freefs->filt );
		              freefs->filt = NULL;
		              freefs->lud = NULL;
                            }
                            prevfs = freefs;
                            freefs = freefs->f_next;
		        } while(prevfs->f_next);

		        id->filters = NULL;
		                                    
			break;

		}
		break;

	default:
		switch( c->type ) {
		case CLOG_DB:
		        if ( CONFIG_ONLINE_ADD( c )) {
		                id->backend = select_backend( &c->value_ndn, 0 );
        			if ( !id->backend ) {
	        			snprintf( c->cr_msg, sizeof( c->cr_msg  ), "<%s> no matching backend found for suffix",
		        			c->argv[0] );
                                        Debug( LDAP_DEBUG_ANY, "%s: %s \"%s\"\n",
					        c->log, c->cr_msg, c->value_dn.bv_val );
        				rc = 1;
                                }
			}
			else
			{
			        id->backend_suffix = c->value_ndn;
			}
			ch_free( c->value_dn.bv_val );

			break;
		case CLOG_CONVREPLACE:
			id->deladd = c->value_int;
			break;
		case CLOG_RETENTION:
			id->retain = c->value_int;
			break;
		case CLOG_PRUNE:
			id->prune = c->value_int;
                        if ( slapMode & SLAP_SERVER_MODE ) {
                            struct re_s *re = id->task;
                            if ( re )
                                re->interval.tv_sec = id->prune;
                            else
                                id->task = ldap_pvt_runqueue_insert( &slapd_rq, 
                                    id->prune, prune_changelog, id, "prune_changelog", 
                                    id->backend ? id->backend->be_suffix[0].bv_val : 
                                        c->be->be_suffix[0].bv_val );
                        }

			break;
		case CLOG_DUMPFILTER:
                        if (ldap_url_parse( c->argv[1], &lud ) == 0) {
                            filter_st *fst;
                
                            f = str2filter( lud->lud_filter );

                            if (!f) {
                                Debug(LDAP_DEBUG_ANY, "Cannot parse LDAP filter \"%s\"\n",
                                    lud->lud_filter, NULL, NULL );
                                rc = 1;
                            } else {

                                Debug(LDAP_DEBUG_ANY, "Added changelog filter \"%s\"\n",
                                    c->argv[1], NULL, NULL );

                                fst = ch_calloc( 1, sizeof( filter_st ) );
                                fst->filt = f;
                                fst->lud = lud;
                    
                                if (id->filters == NULL) {
                                    fst->f_next = NULL;
                                    id->filters = fst;
                                } else {
                                    filter_st *ff;
                                    for(ff = id->filters; ff->f_next; ff = ff->f_next);
                                    ff->f_next = fst;
                                }
                            }

                        } else {
                            Debug(LDAP_DEBUG_ANY, "Cannot parse LDAP URL \"%s\"\n",
                                c->argv[1], NULL, NULL );
                            rc = 1;
                        }

                        break;
		}
		break;
	}

	return rc;
}

static int
changelog_delmod( Operation *op, SlapReply *rs )
{
    slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
    changelog_data *id = on->on_bi.bi_private;
    Backend *cbe = NULL;
    changelog_entry *ne;
    Entry *pe = NULL;
    int rc, len;
    void *priv = op->o_private;
    struct berval csn = BER_BVNULL;
    char csnbuf[ LDAP_LUTIL_CSNSTR_BUFSIZE ];
    id->message="_delmod";

    if (!id->backend)
    {
        Debug(LDAP_DEBUG_TRACE,
              "Error: changelog_db not specified - unable to store entry to changelog\n", NULL, NULL, NULL);

        return SLAP_CB_CONTINUE;
    }

    if (dnIsSuffix( &op->o_req_ndn, id->backend->be_suffix )) {
        Debug(LDAP_DEBUG_TRACE,
              "%s:%d Modification to %s is to changelog - not creating state or CSN\n",
              __FUNCTION__, __LINE__, op->o_req_ndn.bv_val );
        return SLAP_CB_CONTINUE;
    }
            
    if ((op->o_tag == LDAP_REQ_MODIFY) && (!id->deladd))
        return SLAP_CB_CONTINUE;

    ne = ch_calloc( 1, sizeof(changelog_entry) );
    ne->es_id = op->o_opid;
    ne->es_connid = op->o_connid;
    ne->es_e = NULL;

    op->o_private = NULL;
    op->o_bd->bd_info = (BackendInfo *)(on->on_info);
    rc = be_entry_get_rw( op, &op->o_req_ndn, NULL, NULL, 0, &pe );

    if (rc != LDAP_SUCCESS) {
        Debug( LDAP_DEBUG_ANY, "be_entry_get_rw1 for %s returns %d: %s\n",
               op->o_req_ndn.bv_val, rc, ldap_err2string( rc ) );
        
        op->o_bd->bd_info = (BackendInfo *)on;
        op->o_private = priv;
        ch_free(ne);
        return SLAP_CB_CONTINUE;
    } else {
        ne->es_e = entry_dup( pe );
        be_entry_release_r( op, pe );        
        op->o_bd->bd_info = (BackendInfo *)on;
        op->o_private = priv;
    }
    
        /* Save state for this operation */
    ldap_pvt_thread_mutex_lock(&changelog_mutex);
    Debug(LDAP_DEBUG_ANY, "%s Saving state for op %ld, conn %ld\n",
          __FUNCTION__, ne->es_id, ne->es_connid);
    ne->es_next = id->esave;
    id->esave = ne;
    ldap_pvt_thread_mutex_unlock(&changelog_mutex);
    
    return SLAP_CB_CONTINUE;
}

static int
changelog_response(
	Operation *op,
	SlapReply *rs
)
{
    slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
    changelog_data *id = on->on_bi.bi_private;
    Backend *cbe = NULL;
    changelog_entry *ce, *cp;
    char csnbuf[ LDAP_LUTIL_CSNSTR_BUFSIZE ];
    struct berval csn = BER_BVNULL;
    time_t now;
    
    id->message = "_response";
    
    if ((op->o_tag != LDAP_REQ_ADD) && (op->o_tag != LDAP_REQ_DELETE) &&
        (op->o_tag != LDAP_REQ_MODIFY) && (op->o_tag != LDAP_REQ_MODDN)) {
        Debug(LDAP_DEBUG_ANY, "%s:%d\n", __FUNCTION__, __LINE__, 0);
        return SLAP_CB_CONTINUE;
    }
    
    if (!id->backend)
    {
        Debug(LDAP_DEBUG_TRACE,
              "Error: changelog_db not specified - unable to store entry to changelog\n", NULL, NULL, NULL);

        return SLAP_CB_CONTINUE;
    }

    if (dnIsSuffix( &op->o_req_ndn, id->backend->be_suffix )) {
        Debug(LDAP_DEBUG_TRACE,
              "%s:%d Modification to %s is to changelog - not creating state or CSN\n",
              __FUNCTION__, __LINE__, op->o_req_ndn.bv_val );
        return SLAP_CB_CONTINUE;
    }
            
    if (rs->sr_err != LDAP_SUCCESS ) {
        Debug(LDAP_DEBUG_ANY, "%s:%d unsuccessful operation: %d\n", __FUNCTION__, __LINE__, rs->sr_err);
        goto end;
    }
    
    /*
     * Check to see if this operation is a modify on the
     * changelog. If it is, exit immediately to avoid
     * recursion.
     */

    if ((!id->backend) || (cbe = id->backend) == NULL) {
        Debug(LDAP_DEBUG_ANY,
              "Cannot determine backend for changelog DB \"%s\"\n",
              id->backend->be_suffix[0].bv_val, 0, 0);
        goto end;
    }

    add_changelog_entry( op, cbe );

  end:
    /* delete any saved state for this operation */
    ldap_pvt_thread_mutex_lock(&changelog_mutex);
    for(ce = id->esave, cp = NULL; ce; ce = ce->es_next) {
        Debug(LDAP_DEBUG_ANY, "%s State ID = (%ld,%ld)\n",
              __FUNCTION__, ce->es_id, ce->es_connid);
        if ((op->o_opid == ce->es_id) && (op->o_connid == ce->es_connid)) {
            if (cp == NULL)
                id->esave = ce->es_next;
            else
                cp->es_next = ce->es_next;
            
            break;
        }
        cp = ce;
    }
    ldap_pvt_thread_mutex_unlock(&changelog_mutex);
    if (ce) {
        Debug(LDAP_DEBUG_ANY, "Deleting state for op (%ld,%ld)\n", ce->es_id,
              ce->es_connid, 0);
        entry_free(ce->es_e);
        ch_free(ce);        
    }
    
    return(SLAP_CB_CONTINUE);
}

static int
changelog_cancel( Operation *op, SlapReply *rs )
{
    slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
    changelog_data *id = on->on_bi.bi_private;
    changelog_entry *ce, *cp;
    
    /* delete any saved state for this operation */
    ldap_pvt_thread_mutex_lock(&changelog_mutex);
    for(ce = id->esave, cp = NULL; ce; ce = ce->es_next) {
        if ((op->o_opid == ce->es_id) && (op->o_connid == ce->es_connid))  {
            if (cp == NULL)
                id->esave = ce->es_next;
            else
                cp->es_next = ce->es_next;
            
            break;
        }
        cp = ce;
    }
    ldap_pvt_thread_mutex_unlock(&changelog_mutex);
    if (ce) {
        Debug(LDAP_DEBUG_ANY, "Deleting state for op (%ld,%ld)\n", ce->es_id,
              ce->es_connid, 0);
        entry_free(ce->es_e);
        ch_free(ce);        
    }
    
    return(SLAP_CB_CONTINUE);
}

static void
mods2ldif( Modifications *mods, Entry *e, struct berval *bv, BerVarray *aa )
{
    Modifications *ml;
    BerVarray at = NULL;
    int i, j, p;
    struct berval adcn = BER_BVNULL;
    
    bv->bv_val = NULL;
    bv->bv_len = 0;
    
    for ( ml = mods; ml != NULL; ml = ml->sml_next ) {
        char *did, *type = ml->sml_desc->ad_cname.bv_val;

        j = p = 0;
        do {
            if (at == NULL) break; /* empty array */
            if (at[j].bv_val == NULL) break; /* end of array */
            if (ber_bvcmp( &at[j], &(ml->sml_desc->ad_cname) ) == 0) p = 1;
            j++;
        } while (p == 0);

        if (!p) {
            ber_dupbv( &adcn, &ml->sml_desc->ad_cname );
            ber_bvarray_add( &at, &adcn );
        }
        
        switch ( ml->sml_op ) {
            case LDAP_MOD_ADD:
                did = "add"; break;
                
            case LDAP_MOD_DELETE:
                did = "delete"; break;
                
            case LDAP_MOD_REPLACE:
                did = "replace"; break;

            case LDAP_MOD_INCREMENT:
                did = "increment"; break;
        }

        if ((e) && (ml->sml_op == LDAP_MOD_REPLACE)) {
            /*
             * generate a "delete: <attr>", "<attr>: <oldvalues>"
             * followed by a "add: <attr>", "<attr>: <newvalues>"
             */
            Attribute *a = attr_find( e->e_attrs, ml->sml_desc );

            if (a) {
                bv->bv_val = ch_realloc( bv->bv_val, bv->bv_len + strlen( "delete" ) + strlen(type) + 4 );
                sprintf( bv->bv_val + bv->bv_len, "delete: %s\n", type );
                bv->bv_len = strlen( bv->bv_val );

                for(i = 0; a->a_vals[i].bv_val; i++) {
                    int len;
                    char *buf, *bufp;
                    
                    len = LDIF_SIZE_NEEDED( strlen(type),
                                            a->a_vals[i].bv_len );
                    buf = ch_calloc( len + 1, sizeof(char) );
                    bufp = buf;
                    ldif_sput( &bufp, LDIF_PUT_VALUE, type,
                               a->a_vals[i].bv_val, a->a_vals[i].bv_len );
                    *bufp = '\0';
                    
                    bv->bv_val = ch_realloc( bv->bv_val, bv->bv_len + len + 1 );
                    strcpy( bv->bv_val + bv->bv_len, buf );
                    free(buf);
                    bv->bv_len = strlen( bv->bv_val );
                }
                
                bv->bv_val = ch_realloc( bv->bv_val, bv->bv_len + 3 );
                sprintf( bv->bv_val + bv->bv_len, "-\n" );
                bv->bv_len = strlen( bv->bv_val );
            }
            
            bv->bv_val = ch_realloc( bv->bv_val, bv->bv_len + strlen( "add" ) + strlen( type ) + 4 );
            sprintf( bv->bv_val + bv->bv_len, "add: %s\n", type );
            bv->bv_len = strlen( bv->bv_val );

            if ( ml->sml_values ) {
                for ( i = 0 ; ml->sml_values[i].bv_val; i++ ) {
                    int len;
                    char *buf, *bufp;
                    
                    len = LDIF_SIZE_NEEDED( strlen(type),
                                            ml->sml_values[i].bv_len );
                    buf = ch_calloc( len + 1, sizeof(char) );
                    bufp = buf;
                    ldif_sput( &bufp, LDIF_PUT_VALUE, type,
                               ml->sml_values[i].bv_val,
                               ml->sml_values[i].bv_len );
                    *bufp = '\0';
                    
                    bv->bv_val = ch_realloc( bv->bv_val, bv->bv_len + len + 1 );
                    strcpy( bv->bv_val + bv->bv_len, buf );
                    free(buf);
                    bv->bv_len = strlen( bv->bv_val );
                }
            }
        } else {
            bv->bv_val = ch_realloc( bv->bv_val, bv->bv_len + strlen( did ) + strlen( type ) + 4 );
            sprintf( bv->bv_val + bv->bv_len, "%s: %s\n", did, type );
            bv->bv_len = strlen( bv->bv_val );

            if ( ml->sml_values ) {
                for ( i = 0 ; ml->sml_values[i].bv_val; i++ ) {
                    int len;
                    char *buf, *bufp;
                    
                    len = LDIF_SIZE_NEEDED( strlen(type),
                                            ml->sml_values[i].bv_len );
                    buf = ch_calloc( len + 1, sizeof(char) );
                    bufp = buf;
                    ldif_sput( &bufp, LDIF_PUT_VALUE, type,
                               ml->sml_values[i].bv_val,
                               ml->sml_values[i].bv_len );
                    *bufp = '\0';
                    
                    bv->bv_val = ch_realloc( bv->bv_val, bv->bv_len + len + 1 );
                    strcpy( bv->bv_val + bv->bv_len, buf );
                    free(buf);
                    bv->bv_len = strlen( bv->bv_val );
                }
            }
        }
        
        bv->bv_val = ch_realloc( bv->bv_val, bv->bv_len + 3 );
        sprintf( bv->bv_val + bv->bv_len, "-\n" );
        bv->bv_len = strlen( bv->bv_val );
    }

    *aa = at;
}

static void
adds2ldif( Entry *e, struct berval *bv, BerVarray *aa )
{
    Attribute *a;
    int i, j, p;
    char *buf;
    BerVarray at = NULL;
    struct berval adcn = BER_BVNULL;
    
    buf = ch_calloc(strlen("dn: \n") + e->e_name.bv_len + 1, sizeof(char));
    sprintf( buf, "dn: %s\n", e->e_name.bv_val);
    bv->bv_val = buf;
    bv->bv_len = strlen(buf);

    for ( a = e->e_attrs; a; a=a->a_next ) {
        char *type = a->a_desc->ad_cname.bv_val;

        j = p = 0;
        do {
            if (at == NULL) break; /* empty array */
            if (at[j].bv_val == NULL) break; /* end of array */
            if (ber_bvcmp( &at[j], &(a->a_desc->ad_cname) ) == 0) p = 1;
            j++;
        } while (p == 0);

        if (!p) {
            ber_dupbv( &adcn, &a->a_desc->ad_cname );
            ber_bvarray_add( &at, &adcn );
        }
        
        for ( i = 0 ; a->a_vals[i].bv_val; i++ ) {
            int len;
            char *bufp;
                
            len = LDIF_SIZE_NEEDED( strlen(type), a->a_vals[i].bv_len );
            buf = ch_calloc( len + 1, sizeof(char) );
            bufp = buf;
            ldif_sput( &bufp, LDIF_PUT_VALUE, type,
                       a->a_vals[i].bv_val, a->a_vals[i].bv_len );
            *bufp = '\0';

            bv->bv_val = ch_realloc( bv->bv_val, bv->bv_len + len + 1 );
            strcpy( bv->bv_val + bv->bv_len, buf );
            free(buf);
            bv->bv_len = strlen( bv->bv_val );
        }
    }
    if (aa) {
        *aa = at;
    } else
        if (at) ber_bvarray_free(at);
}

static void
del2ldif( Entry *e, BerVarray *aa )
{
    Attribute *a;
    int j, p;
    BerVarray at = NULL;
    struct berval adcn = BER_BVNULL;
    
    for ( a = e->e_attrs; a; a=a->a_next ) {
        char *type = a->a_desc->ad_cname.bv_val;

        j = p = 0;
        do {
            if (at == NULL) break; /* empty array */
            if (at[j].bv_val == NULL) break; /* end of array */
            if (ber_bvcmp( &at[j], &(a->a_desc->ad_cname) ) == 0) p = 1;
            j++;
        } while (p == 0);

        if (!p) {
            ber_dupbv( &adcn, &a->a_desc->ad_cname );
            ber_bvarray_add( &at, &adcn );
        }
    }
    *aa = at;
}

static int
filter_match( Operation *op, Entry *e, filter_st *fs )
{
    filter_st *f;

    if ((!e) || (!fs)) return 0;
    
    for(f = fs; f; f=f->f_next) {
        struct berval bv, pv, nv;
        int i, match = 0, excl = 0;
        BerVarray delattrs = NULL;
        Attribute *a;
        
        ber_str2bv( f->lud->lud_dn, 0, 0, &bv );
        if (dnPrettyNormal( NULL, &bv, &pv, &nv, NULL ) != 0) continue;
        ch_free( pv.bv_val );
        switch(f->lud->lud_scope) {
            case LDAP_SCOPE_BASE:
                match = dn_match( &e->e_nname, &nv );
                break;
            case LDAP_SCOPE_ONE:
                dnParent( &e->e_nname, &pv );
                match = dn_match( &pv, &nv );
                break;
            case LDAP_SCOPE_SUBTREE:
                match = dnIsSuffix( &e->e_nname, &nv );
                break;
        }
        ch_free( nv.bv_val );
        if (!match) continue;
        /* got a match on scope -- now try the filter */
        if (test_filter( op, e, f->filt ) != LDAP_COMPARE_TRUE) return 0;

        /*
         * Now filter out the entry attributes if a list is present
         * in the LDAP filter - if attributes were specified. if they
         * weren't then we just store all of the attrs.
         */
        if (! f->lud->lud_attrs) return 1;
        
        if (f->lud->lud_exts)
            for(i=0; f->lud->lud_exts[i]; i++)
                if (strcasecmp( f->lud->lud_exts[i], "X-EXCLUDE-ATTRIBUTES" ) == 0) {
                    excl = 1;
                    break;
                }
        
        if (excl) {
            for(a = e->e_attrs; a; a = a->a_next) {
                struct berval *aname = &a->a_desc->ad_cname;
                int add = 0;
                
                for(i=0; f->lud->lud_attrs[i]; i++)
                    if (strcasecmp(aname->bv_val, f->lud->lud_attrs[i]) == 0) {
                        add = 1;
                        break;
                    }
                
                if (add) {
                    ber_str2bv(aname->bv_val, aname->bv_len, 1, &bv);
                    ber_bvarray_add(&delattrs, &bv);
                }
            }
        } else {
            for(a = e->e_attrs; a; a = a->a_next) {
                struct berval *aname = &a->a_desc->ad_cname;
                
                for(i=0; f->lud->lud_attrs[i]; i++)
                    if (strcasecmp(aname->bv_val, f->lud->lud_attrs[i]) == 0)
                        break;

                if (!f->lud->lud_attrs[i]) {
                    ber_str2bv(aname->bv_val, aname->bv_len, 1, &bv);
                    ber_bvarray_add(&delattrs, &bv);
                }
            }
        }

        if (delattrs) {
            for(i=0; delattrs[i].bv_val; i++) {
                Attribute *p = NULL;
                
                for(a=e->e_attrs; a; a=a->a_next) {
                    struct berval *aname = &a->a_desc->ad_cname;

                    if (strcasecmp(aname->bv_val, delattrs[i].bv_val) == 0) {
                        struct berval *aname = &a->a_desc->ad_cname;
                        
                        if (!p)
                            e->e_attrs = a->a_next;
                        else
                            p->a_next = a->a_next;
                        attr_free(a);
                        break;
                    }
                    p = a;
                }
            }
            
            ber_bvarray_free(delattrs);
        }
        
        return 1;
    }

    return 0;
}

static int
add_changelog_entry( Operation *op, Backend *be ) 
{
    Operation nop = *op;
    Entry *e = NULL, *ep;
    slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
    changelog_data *id = on->on_bi.bi_private;
#ifdef HAVE_LONG_LONG
    const char *fmt = "changeNumber = %llu, %s";
    unsigned long long cn, thiscn;
#else
    const char *fmt = "changeNumber = %lu, %s";
    unsigned long cn, thiscn;
#endif /* HAVE_LONG_LONG */
    struct berval bv, csn = BER_BVNULL;
    struct berval bvDeleteOldRDN = BER_BVNULL;

    char *ldif;
    int i, len, rc, ln, foundit = 0;
    SlapReply nrs = { REP_RESULT };
    time_t now;
    struct tm *ltm;
    char timebuf[ LDAP_LUTIL_GENTIME_BUFSIZE ];
    BerVarray attrs = NULL;
    changelog_entry *ce = NULL;
    void *priv = op->o_private;
    slap_callback cb = { NULL, slap_null_cb, NULL, NULL };
    
    /*
     * We don't care about Binds, Searches, Abandons and Compares
     * since they wouldn't get recorded.
     */

    nop.o_private = NULL;
    nop.o_bd = be;
    
    get_change_numbers( &nop, be, id );
    if (id->got_change_numbers == 0) {
        Debug(LDAP_DEBUG_ANY, "Cannot update changelog - no numbers available\n", 0, 0, 0);
        goto end;
    }

    e = entry_alloc();
    assert( e );
    e->e_id = NOID;
    ldap_pvt_thread_mutex_lock(&changenum_mutex);
    thiscn = id->last_change_num + 1;
    ldap_pvt_thread_mutex_unlock(&changenum_mutex);
    
    for(cn=thiscn,ln=1; cn > 0; cn /= 10, ln++);
    bv.bv_len = strlen(fmt) + ln + strlen(id->backend->be_suffix[0].bv_val);
    bv.bv_val = ch_calloc( bv.bv_len + 1, sizeof(char) );
    sprintf(bv.bv_val, fmt, thiscn, id->backend->be_suffix[0].bv_val);
    Debug( LDAP_DEBUG_ANY, "Length of DN = %d:%s\n", (int)bv.bv_len, bv.bv_val, 0);
    bv.bv_len = strlen(bv.bv_val);
    rc = dnPrettyNormal( NULL, &bv, &e->e_name, &e->e_nname, NULL );
    ch_free(bv.bv_val);
    
    e->e_nname.bv_len = strlen(e->e_nname.bv_val);
    
    e->e_ocflags = 0;
    e->e_bv.bv_len = 0;
    e->e_bv.bv_val = NULL;    
    e->e_attrs = NULL;
    e->e_private = NULL;

    ber_str2bv( "top", strlen("top"), 0, &bv );
    attr_merge_one( e, slap_schema.si_ad_objectClass, &bv, NULL );
    ber_str2bv( "changeLogEntry", strlen("changeLogEntry"), 0, &bv );
    attr_merge_one( e, slap_schema.si_ad_objectClass, &bv, NULL );
    
    ber_str2bv( "changeLogEntry", strlen("changeLogEntry"), 0, &bv );
    attr_merge_one( e, slap_schema.si_ad_structuralObjectClass, &bv, NULL );
    
    bv.bv_val = ch_calloc( ln+1, sizeof(char));
#ifdef HAVE_LONG_LONG
    sprintf(bv.bv_val, "%llu", thiscn);
#else
    sprintf(bv.bv_val, "%lu", thiscn);
#endif /* HAVE_LONG_LONG */
    bv.bv_len = strlen(bv.bv_val);
    attr_merge_one( e, id->si_ad_changeNumber, &bv, NULL );
    ch_free(bv.bv_val);
    
    attr_merge_one( e, slap_schema.si_ad_modifiersName, &op->o_dn, &op->o_ndn );

    now = slap_get_time();
    ldap_pvt_thread_mutex_lock( &gmtime_mutex );
    ltm = gmtime( &now );
    lutil_gentime( timebuf, sizeof(timebuf), ltm );
    ldap_pvt_thread_mutex_unlock( &gmtime_mutex );
    bv.bv_val = timebuf;
    bv.bv_len = strlen( timebuf );
    attr_merge_one( e, slap_schema.si_ad_createTimestamp, &bv, NULL );
    
    ber_dupbv( &bv, &be->be_rootdn );
    attr_merge_one( e, slap_schema.si_ad_creatorsName, &bv, NULL );
    ch_free(bv.bv_val);

    struct berval maxcsn;
    char cbuf[LDAP_LUTIL_CSNSTR_BUFSIZE];

    cbuf[0] = '\0';
    maxcsn.bv_val = cbuf;
    maxcsn.bv_len = sizeof(cbuf);

    slap_get_commit_csn( op, &maxcsn, &foundit );

    if ( BER_BVISEMPTY( &maxcsn ) )
        attr_merge_one( e, id->si_ad_changeCSN, &csn, NULL );

    switch( op->o_tag ) {
        case LDAP_REQ_ADD:
            ber_str2bv( "add", strlen("add"), 0, &bv );
            break;
        case LDAP_REQ_DELETE:
            ber_str2bv( "delete", strlen("delete"), 0, &bv );
            break;
        case LDAP_REQ_MODIFY:
            ber_str2bv( "modify", strlen("modify"), 0, &bv );
            break;
        case LDAP_REQ_MODRDN:
            ber_str2bv( "modrdn", strlen("modrdn"), 0, &bv );
            break;
    }

    attr_merge_one( e, id->si_ad_changeType, &bv, NULL );

    bv.bv_len = 0;
    switch( op->o_tag ) {
        case LDAP_REQ_ADD:
            adds2ldif( op->ora_e, &bv, &attrs );
            break;
        case LDAP_REQ_MODIFY:
            ep = NULL;
            if (id->deladd) {
                ldap_pvt_thread_mutex_lock(&changelog_mutex);
                Debug( LDAP_DEBUG_ANY, "%s:%d Searching for %d\n", __FUNCTION__, (int)__LINE__, (int)op->o_opid);
                for(ce = id->esave; ce; ce = ce->es_next) {
                    if ((op->o_opid == ce->es_id) && (op->o_connid == ce->es_connid)) {
                        Debug( LDAP_DEBUG_ANY, "%s:%d Got match\n", __FUNCTION__, __LINE__, 0);
                        ep = ce->es_e;
                        break;
                    }
                }
                ldap_pvt_thread_mutex_unlock(&changelog_mutex);

                if ((ep) && (filter_match(op, ep, id->filters))) {
                    adds2ldif( ep, &bv, NULL );
                    attr_merge_one( e, id->si_ad_oldEntry, &bv, NULL );
                }
                
            }
            mods2ldif( op->orm_modlist, ep, &bv, &attrs );
            break;
        case LDAP_REQ_DELETE:
            ep = NULL;
            ldap_pvt_thread_mutex_lock(&changelog_mutex);
            for(ce = id->esave; ce; ce = ce->es_next) {
                if ((op->o_opid == ce->es_id) && (op->o_connid == ce->es_connid)) {
                    Debug( LDAP_DEBUG_ANY, "%s:%d Got match\n", __FUNCTION__, __LINE__, 0);
                    ep = ce->es_e;
                    break;
                }
            }
            
            ldap_pvt_thread_mutex_unlock(&changelog_mutex);
            if (ep) {
                if (filter_match(op, ep, id->filters)) {
                    adds2ldif( ep, &bv, &attrs );
                    attr_merge_one( e, id->si_ad_oldEntry, &bv, NULL );
                    ch_free( bv.bv_val );
                    bv.bv_val = NULL;
                    bv.bv_len = 0;
                } else
                    del2ldif( ep, &attrs );
            }
            
            break;
        case LDAP_REQ_MODRDN:
            len = strlen("newrdn: \n") + op->orr_newrdn.bv_len;
            len += strlen("deleteoldrdn: \n") + 1;
            if (op->orr_newSup)
                len += strlen("newsuperior: \n") + op->orr_newSup->bv_len;
            bv.bv_val = ch_calloc( len + 1, sizeof(char) );

            if (op->orr_newSup)
            {
                sprintf(bv.bv_val,
                        "newrdn: %s\ndeleteoldrdn: %d\nnewsuperior: %s\n",
                        op->orr_newrdn.bv_val,
                        op->orr_deleteoldrdn ? 1 : 0,
                        op->orr_newSup->bv_val);

                attr_merge_one( e, id->si_ad_newSuperior, op->orr_newSup, NULL );

            }
            else
            {
                sprintf(bv.bv_val, "newrdn: %s\ndeleteoldrdn: %d\n",
                        op->orr_newrdn.bv_val,
                        op->orr_deleteoldrdn ? 1 : 0);
            }
            bv.bv_len = strlen(bv.bv_val);

            if (op->orr_deleteoldrdn)
                ber_str2bv("1",0,0,&bvDeleteOldRDN);
            else
                ber_str2bv("0",0,0,&bvDeleteOldRDN);

            attr_merge_one( e, id->si_ad_newRDN, &op->orr_newrdn, NULL );
            attr_merge_one( e, id->si_ad_deleteOldRDN, &bvDeleteOldRDN, NULL );

            break;
    }
    
    if (bv.bv_len) {
        attr_merge_one( e, id->si_ad_changes, &bv, NULL );
        ber_memfree( bv.bv_val );
    }
    
    attr_merge_one( e, id->si_ad_targetDN, &op->o_req_dn, &op->o_req_ndn );
    
    nrs.sr_type = REP_RESULT;
    nop.o_dn = be->be_rootdn;
    nop.o_ndn = be->be_rootndn;
    nop.o_req_dn = e->e_name;
    nop.o_req_ndn = e->e_nname;
    
    nop.o_tag = LDAP_REQ_ADD;
    nop.ora_e = e;
    nop.o_callback = &cb;

    if (attrs) attr_merge( e, id->si_ad_changedAttribute, attrs, NULL );

    rc = be->be_add( &nop, &nrs );
    if (rc == LDAP_SUCCESS) {
        ldap_pvt_thread_mutex_lock(&changenum_mutex);
        id->last_change_num++;
        if (id->first_change_num == 0)
            id->first_change_num = id->last_change_num;
            commit_change_numbers( &nop, be, id );
        ldap_pvt_thread_mutex_unlock(&changenum_mutex);
    }
  end:
    if (attrs) ber_bvarray_free( attrs );

    if ( e == op->ora_e )
            entry_free( e );

    return LDAP_SUCCESS;
}

static int
changelog_search_result( Operation *op, SlapReply *rs )
{
    cb_data_st *d = (cb_data_st *)(op->o_callback->sc_private);
    BerValue bv;
    Attribute *a;
    int i;
    
    if (rs->sr_type != REP_SEARCH || !rs->sr_entry) return 0;
    ber_dupbv( &bv, &rs->sr_entry->e_nname );
    ber_bvarray_add( &d->ba, &bv );

    if ((a = attr_find( rs->sr_entry->e_attrs, d->si_ad_changeNumber )) == NULL) {
        Debug(LDAP_DEBUG_ANY, "Changelog entry has no changenumber value: changelog is corrupt\n",
              0, 0, 0);
        return 0;
    }

    for(i=0; !BER_BVISNULL(&a->a_vals[i]); i++) {
#ifdef HAVE_LONG_LONG
        unsigned long long v = strtoll( a->a_vals[i].bv_val, NULL, 10 );
#else
        unsigned long v = strtol( a->a_vals[i].bv_val, NULL, 10 );
#endif /* HAVE_LONG_LONG */
        
        if (v > d->largest) d->largest = v;
    }
    
    return 0;
}

static void *
prune_changelog( void *ctx, void *arg )
{
    struct re_s *rtask = arg;
    struct changelog_data *id = rtask->arg;

    Connection conn = { 0 };
    OperationBuffer opbuf;
    Operation *op;

    connection_fake_init (&conn, &opbuf, ctx);
    op = &opbuf.ob_op;
    op->o_bd = id->backend;

    time_t then;
    char thenstr[ LDAP_LUTIL_GENTIME_BUFSIZE ];
    char *filt;
    const char *fmt = "(&(objectClass=changeLogEntry)(createTimeStamp<=%s))";
    struct tm *tm;

    slap_callback cb = { NULL, NULL, NULL, NULL };
    SlapReply nrs = { REP_RESULT };
    int i, rc;
    cb_data_st cb_data;

    Debug(LDAP_DEBUG_ANY, "Pruning changelog %s\n", id->backend->be_suffix[0].bv_val, NULL, NULL );

    then = slap_get_time() - id->retain;
    ldap_pvt_thread_mutex_lock( &gmtime_mutex );
    tm = gmtime(&then);
    lutil_gentime( thenstr, sizeof(thenstr), tm );
    ldap_pvt_thread_mutex_unlock( &gmtime_mutex );

    filt = ch_calloc( strlen( fmt ) + strlen(thenstr) + 1, sizeof(char) );
    sprintf(filt, fmt, thenstr );

    struct berval filter;
    ber_str2bv(filt,strlen(filt),1,&filter);

    ber_dupbv_x( &op->ors_filterstr, &filter, op->o_tmpmemctx );

    op->ors_filter = str2filter_x( op, filt );

    op->ors_attrs = slap_anlist_no_attrs;
    op->ors_attrsonly = 1;

    cb_data.ba = NULL;
    cb_data.largest = 0;
    cb_data.si_ad_changeNumber = id->si_ad_changeNumber;

    cb.sc_private = &cb_data;
    cb.sc_response = changelog_search_result;

    op->o_callback = &cb;
    op->o_tag = LDAP_REQ_SEARCH;
    op->ors_scope = LDAP_SCOPE_ONE;
    op->ors_deref = LDAP_DEREF_NEVER;
    op->ors_limit = NULL;
    op->ors_slimit = SLAP_NO_LIMIT;
    op->ors_tlimit = SLAP_NO_LIMIT;
    op->o_abandon = op->o_cancel = 0;
    op->o_dn = id->backend->be_rootdn;
    op->o_ndn = id->backend->be_rootndn;

    ber_dupbv_x( &op->o_req_dn, &op->o_bd->be_suffix[ 0 ], op->o_tmpmemctx );
    ber_dupbv_x( &op->o_req_ndn, &op->o_bd->be_nsuffix[ 0 ], op->o_tmpmemctx );

    nrs.sr_type = REP_RESULT;
    
    rc = op->o_bd->be_search(op, &nrs);

    ch_free(filt);
    ber_memfree(filter.bv_val);

    if (rc != LDAP_SUCCESS) {
        Debug(LDAP_DEBUG_ANY, "Result for prune search = %d: %s\n",
              rc, ldap_err2string(rc), 0);
    } else {
        cb.sc_response = slap_null_cb;
    
        for(i=0; cb_data.ba && cb_data.ba[i].bv_val; i++) {
            SlapReply rs = { REP_RESULT };

            op->o_callback = &cb;
            op->o_tag = LDAP_REQ_DELETE;
            op->o_dn = op->o_bd->be_rootdn;
            op->o_ndn = op->o_bd->be_rootndn;
            op->o_req_dn = cb_data.ba[i];
            op->o_req_ndn = cb_data.ba[i];
            
            if ((rc = op->o_bd->be_delete(op, &rs)) != LDAP_SUCCESS) {
                Debug(LDAP_DEBUG_ANY,
                      "Result for prune deletion of %s = %d: %s\n",
                      cb_data.ba[i].bv_val, rc, ldap_err2string(rc));
            }
        }

        if (cb_data.ba) {
            ber_bvarray_free(cb_data.ba);
        }
    }
  end:

    ldap_pvt_thread_mutex_lock( &slapd_rq.rq_mutex );
    ldap_pvt_runqueue_stoptask( &slapd_rq, rtask );
    ldap_pvt_thread_mutex_unlock( &slapd_rq.rq_mutex );

    return NULL;

}

static void
get_change_numbers( Operation *op, Backend *be, changelog_data *id )
{
    slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
    int i, rc;
    Entry *e = NULL;
    Attribute *a;

    if (id->got_change_numbers) return; /* already done */

    ldap_pvt_thread_mutex_lock( &changenum_mutex );

    rc = be_entry_get_rw( op, &id->backend->be_nsuffix[0], NULL, NULL, 0, &e );
    
    if (rc != LDAP_SUCCESS) {
        Debug( LDAP_DEBUG_ANY, "be_entry_get_rw for %s returns %d: %s\n",
               op->o_req_ndn.bv_val, rc, ldap_err2string( rc ) );
        goto end;
    }

    if ((a = attr_find( e->e_attrs, id->si_ad_firstChangeNumber )) != NULL) {
        for(i=0; ! BER_BVISNULL(&a->a_vals[i]); i++) {
#ifdef HAVE_LONG_LONG
            id->first_change_num = strtoll( a->a_vals[i].bv_val, NULL, 10 );
#else
            id->first_change_num = strtol( a->a_vals[i].bv_val, NULL, 10 );
#endif            
        }
    }

    if ((a = attr_find( e->e_attrs, id->si_ad_lastChangeNumber )) != NULL) {
        for(i=0; ! BER_BVISNULL(&a->a_vals[i]); i++) {
#ifdef HAVE_LONG_LONG
            id->last_change_num = strtoll( a->a_vals[i].bv_val, NULL, 10 );
#else
            id->last_change_num = strtol( a->a_vals[i].bv_val, NULL, 10 );
#endif            
        }
    }

    
    id->got_change_numbers = 1;
  end:
    if (e) be_entry_release_r( op, e );
    ldap_pvt_thread_mutex_unlock( &changenum_mutex );
}

#ifdef HAVE_LONG_LONG
static void l2bv( struct berval *bv, unsigned long long l )
#else
static void l2bv( struct berval *bv, unsigned long l )
#endif
{
    char *buf;
    int ln;
#ifdef HAVE_LONG_LONG
    unsigned long long ll = l;
#else
    unsigned long ll = l;
#endif /* HAVE_LONG_LONG */    

    for(ln=1; ll > 0; ln++, ll/=10);

    buf = ch_calloc( ln+1, sizeof(char));
#ifdef HAVE_LONG_LONG
    sprintf(buf, "%llu", l);
#else
    sprintf(buf, "%lu", l);
#endif /* HAVE_LONG_LONG */
    bv->bv_val = buf;
    bv->bv_len = strlen(buf);
}

static void
commit_change_numbers( Operation *op, Backend *be, changelog_data *id )
{
    slap_overinst *on = (slap_overinst *) op->o_bd->bd_info;
    Modifications *mods, *m;
    slap_callback cb = { NULL, slap_null_cb, NULL, NULL };
    SlapReply nrs = { REP_RESULT };
    AttributeDescription *ad_first = NULL, *ad_last = NULL;
    const char *txt;
    BerVarray v = NULL, nv = NULL, v2 = NULL, nv2 = NULL;
    struct berval bv, bv2;
    int rc;
    
    op->o_req_dn = *(id->backend->be_suffix);
    op->o_req_ndn = *(id->backend->be_nsuffix);
    
    op->o_dn = be->be_rootdn;
    op->o_ndn = be->be_rootndn;

    op->o_callback = &cb;

    op->o_private = NULL;
    op->o_bd = be;
    op->o_tag = LDAP_REQ_MODIFY;
    
    m = ch_calloc( sizeof( Modifications), 1 );
    m->sml_op = LDAP_MOD_REPLACE;
    m->sml_type = id->si_ad_firstChangeNumber->ad_cname;
    m->sml_desc = id->si_ad_firstChangeNumber;
    m->sml_next = NULL;
    l2bv( &bv, id->first_change_num );
    ber_dupbv( &bv2, &bv );
    ber_bvarray_add( &v, &bv );
    ber_bvarray_add( &nv, &bv2 );
    m->sml_values = v;
    m->sml_nvalues = nv;
    m->sml_numvals = 1;
    
    mods = ch_calloc( sizeof( Modifications), 1 );
    mods->sml_op = LDAP_MOD_REPLACE;
    mods->sml_type = id->si_ad_lastChangeNumber->ad_cname;
    mods->sml_desc = id->si_ad_lastChangeNumber;
    mods->sml_next = m;
    l2bv( &bv, id->last_change_num );
    ber_dupbv( &bv2, &bv );
    ber_bvarray_add( &v2, &bv );
    ber_bvarray_add( &nv2, &bv2 );
    mods->sml_values = v2;
    mods->sml_nvalues = nv2;
    mods->sml_numvals = 1;

    op->orm_modlist = mods;
    
    rc = be->be_modify( op, &nrs );

    if (rc != LDAP_SUCCESS) {
        Debug(LDAP_DEBUG_ANY, "Cannot update %s change numbers [Changelog may be corrupt]: %d: %s\n",
              id->backend->be_suffix[0].bv_val, rc, ldap_err2string(rc));
    }
    
    slap_mods_free( mods, 1 );
}

static int
changelog_db_init( BackendDB *be, ConfigReply *cr ) 
{
    slap_overinst *on = (slap_overinst *)be->bd_info;
    changelog_data *id = ch_malloc(sizeof(changelog_data));
    const char *txt = NULL;
    
    id->backend = NULL;
    id->esave = NULL;
    id->message = "_config";
    id->deladd = 0;
    id->lastprune = 0; /* ensures a prune at startup */
    id->prune = 300; /* prune at most every 5 minutes */
    id->retain = 1209600; /* retain changelog records for 2 weeks */
    id->first_change_num = 0;
    id->last_change_num = 0;
    id->got_change_numbers = 0;
    id->filters = NULL;
    id->si_ad_firstChangeNumber = NULL;
    id->si_ad_lastChangeNumber = NULL;
    id->si_ad_changeNumber = NULL;
    id->si_ad_changeCSN = NULL;
    id->si_ad_changeType = NULL;
    id->si_ad_changes = NULL;
    id->si_ad_targetDN = NULL;
    id->si_ad_changedAttribute = NULL;
    id->si_ad_oldEntry = NULL;
    id->si_ad_newRDN = NULL;
    id->si_ad_newSuperior = NULL;
    id->si_ad_deleteOldRDN = NULL;
    
    if (slap_str2ad( "firstChangeNumber", &id->si_ad_firstChangeNumber, &txt) != LDAP_SUCCESS ) {
        Debug(LDAP_DEBUG_ANY, "cannot locate attribute \"firstChangeNumber\"\n", 0, 0, 0);
        return -1;
    }
    
    if (slap_str2ad( "lastChangeNumber", &id->si_ad_lastChangeNumber, &txt) != LDAP_SUCCESS ) {
        Debug(LDAP_DEBUG_ANY, "cannot locate attribute \"lastChangeNumber\"\n", 0, 0, 0);
        return -1;
    }
    
    if (slap_str2ad( "changeNumber", &id->si_ad_changeNumber, &txt) != LDAP_SUCCESS ) {
        Debug(LDAP_DEBUG_ANY, "cannot locate attribute \"changeNumber\"\n", 0, 0, 0);
        return -1;
    }
    
    if (slap_str2ad( "changeCSN", &id->si_ad_changeCSN, &txt) != LDAP_SUCCESS ) {
        Debug(LDAP_DEBUG_ANY, "cannot locate attribute \"changeCSN\"\n", 0, 0, 0);
        return -1;
    }
    
    if (slap_str2ad( "changeType", &id->si_ad_changeType, &txt) != LDAP_SUCCESS ) {
        Debug(LDAP_DEBUG_ANY, "cannot locate attribute \"changeType\"\n", 0, 0, 0);
        return -1;
    }
    
    if (slap_str2ad( "changes", &id->si_ad_changes, &txt) != LDAP_SUCCESS ) {
        Debug(LDAP_DEBUG_ANY, "cannot locate attribute \"changes\"\n", 0, 0, 0);
        return -1;
    }
    
    if (slap_str2ad( "targetDN", &id->si_ad_targetDN, &txt) != LDAP_SUCCESS ) {
        Debug(LDAP_DEBUG_ANY, "cannot locate attribute \"targetDN\"\n", 0, 0, 0);
        return -1;
    }
    
    if (slap_str2ad( "changedAttribute", &id->si_ad_changedAttribute, &txt) != LDAP_SUCCESS ) {
        Debug(LDAP_DEBUG_ANY, "cannot locate attribute \"changedAttribute\"\n", 0, 0, 0);
        return -1;
    }
    
    if (slap_str2ad( "oldEntry", &id->si_ad_oldEntry, &txt) != LDAP_SUCCESS ) {
        Debug(LDAP_DEBUG_ANY, "cannot locate attribute \"oldEntry\"\n", 0, 0, 0);
        return -1;
    }

    if (slap_str2ad( "newRDN", &id->si_ad_newRDN, &txt) != LDAP_SUCCESS ) {
        Debug(LDAP_DEBUG_ANY, "cannot locate attribute \"newRDN\"\n", 0, 0, 0);
        return -1;
    }


    if (slap_str2ad( "newSuperior", &id->si_ad_newSuperior, &txt) != LDAP_SUCCESS ) {
        Debug(LDAP_DEBUG_ANY, "cannot locate attribute \"newSuperior\"\n", 0, 0, 0);
        return -1;
    }
    
    if (slap_str2ad( "deleteOldRDN", &id->si_ad_deleteOldRDN, &txt) != LDAP_SUCCESS ) {
        Debug(LDAP_DEBUG_ANY, "cannot locate attribute \"deleteOldRDN\"\n", 0, 0, 0);
        return -1;
    }

    on->on_bi.bi_private = id;

    return(0);
}

/* Create the root entry for the changelog_db if it's missing */
static void *
changelog_db_createroot(
        void *ctx,
        void *arg )
{
        struct re_s *rtask = arg;
        slap_overinst *on = rtask->arg;
        changelog_data *id = on->on_bi.bi_private;

	Connection conn = { 0 };
	OperationBuffer opbuf;
	Operation *op;

	Entry *e;
	int rc;

        struct berval val,dsedn,dsendn;

	if ( slapMode & SLAP_TOOL_MODE )
		return 0;

	connection_fake_init( &conn, &opbuf, ctx );
        op = &opbuf.ob_op;
	op->o_bd = id->backend;
	op->o_dn = id->backend->be_rootdn;
	op->o_ndn = id->backend->be_rootndn;

	rc = be_entry_get_rw( op, id->backend->be_nsuffix, NULL, NULL, 0, &e );

	if ( e ) {
		be_entry_release_rw( op, e, 0 );
	} else {
	        /* create initial changelog root */

		SlapReply rs = {REP_RESULT};
		struct berval rdn, nrdn, attr, attr_fcn, attr_lcn;
		char *ptr;
		AttributeDescription *ad = NULL;
		const char *text = NULL;
		Entry *e_ctx;

                e = entry_alloc();

		e->e_name = id->backend->be_rootdn;
		e->e_nname = id->backend->be_rootndn;

		attr_merge_one( e, slap_schema.si_ad_objectClass,
			&clog_container->soc_cname, NULL );

		dnRdn( &e->e_name, &rdn );
		dnRdn( &e->e_nname, &nrdn );
		ptr = ber_bvchr( &rdn, '=' );

		assert( ptr != NULL );

		attr.bv_val = rdn.bv_val;
		attr.bv_len = ptr - rdn.bv_val;

		slap_bv2ad( &attr, &ad, &text );

		rdn.bv_val = ptr+1;
		rdn.bv_len -= attr.bv_len + 1;
		ptr = ber_bvchr( &nrdn, '=' );
		nrdn.bv_len -= ptr - nrdn.bv_val + 1;
		nrdn.bv_val = ptr+1;
		attr_merge_one( e, ad, &rdn, &nrdn );

		attr_fcn.bv_val = "0";
		attr_fcn.bv_len = 1;
		attr_merge_one( e, ad_firstChangeNumber, &attr_fcn, NULL );

		attr_lcn.bv_val = "0";
		attr_lcn.bv_len = 1;
		attr_merge_one( e, ad_lastChangeNumber, &attr_lcn, NULL );

		op->ora_e = e;
		op->o_req_dn = e->e_name;
		op->o_req_ndn = e->e_nname;
                op->o_callback = &nullsc;

                SLAP_DBFLAGS( op->o_bd ) |= SLAP_DBFLAG_NOLASTMOD;

		rc = op->o_bd->be_add( op, &rs );

                SLAP_DBFLAGS( op->o_bd ) ^= SLAP_DBFLAG_NOLASTMOD;

                if ( e == op->ora_e )
                        entry_free( e );
                                    
	}

        ldap_pvt_thread_mutex_lock( &slapd_rq.rq_mutex );
        ldap_pvt_runqueue_stoptask( &slapd_rq, rtask );
        ldap_pvt_runqueue_remove( &slapd_rq, rtask );
        ldap_pvt_thread_mutex_unlock( &slapd_rq.rq_mutex );

        return NULL;

}

static int
changelog_db_open(
	BackendDB *be,
	ConfigReply *cr
)
{
	slap_overinst *on = (slap_overinst *)be->bd_info;
	changelog_data *id = on->on_bi.bi_private;

        if ( !BER_BVISEMPTY( &id->backend_suffix )) {
                id->backend = select_backend( &id->backend_suffix, 0 );
                ch_free( id->backend_suffix.bv_val );
                BER_BVZERO( &id->backend_suffix );
        }
        if ( id->backend == NULL ) {
                Debug( LDAP_DEBUG_ANY,
                        "changelog: \"changelog_db <suffix>\" missing or invalid.\n",
                        0, 0, 0 );   
                return 1;
        }

        if ( slapMode & SLAP_TOOL_MODE )   
                return 0;

        if ( BER_BVISEMPTY( &id->backend->be_rootndn )) {
                ber_dupbv( &id->backend->be_rootdn, id->backend->be_suffix );
                ber_dupbv( &id->backend->be_rootndn, id->backend->be_nsuffix );
        }

        ldap_pvt_thread_mutex_lock( &slapd_rq.rq_mutex );
        ldap_pvt_runqueue_insert( &slapd_rq, 3600, changelog_db_createroot, on,
                "changelog_db_createroot", id->backend->be_suffix[0].bv_val );
        ldap_pvt_thread_mutex_unlock( &slapd_rq.rq_mutex );

        return 0;   
}

static int
changelog_db_destroy(
	BackendDB *be,
	ConfigReply *cr
)
{
	slap_overinst *on = (slap_overinst *)be->bd_info;
	changelog_data *id = on->on_bi.bi_private;

        filter_st *freefs, *prevfs;
 
        struct re_s *re = id->task;
        id->task = NULL;
                                                                
        if ( ldap_pvt_runqueue_isrunning( &slapd_rq, re ))
                ldap_pvt_runqueue_stoptask( &slapd_rq, re );
        ldap_pvt_runqueue_remove( &slapd_rq, re );

        if ( id->filters ) {
            freefs = NULL;
            prevfs = NULL;

            freefs = id->filters;

            do
            {
                if (prevfs) {
                    ch_free(prevfs);
                }

                if ( freefs->filt) {
                    filter_free( freefs->filt );
                    ldap_free_urldesc(  freefs->lud );
                    freefs->filt = NULL;
                    freefs->lud = NULL;
                }
                prevfs = freefs;
                freefs = freefs->f_next;
            } while (prevfs->f_next);

            ch_free(prevfs);
            freefs = NULL;
        }

	ldap_pvt_thread_mutex_destroy( &changelog_mutex );
	ldap_pvt_thread_mutex_destroy( &changenum_mutex );
	
	free( id );

	return LDAP_SUCCESS;
}

int changelog_initialize() {
        int rc, i;

	/* statically declared just after the #includes at top */
	changelog.on_bi.bi_type = "changelog";
        changelog.on_bi.bi_db_init = changelog_db_init;
        changelog.on_bi.bi_db_destroy = changelog_db_destroy;
        changelog.on_bi.bi_db_open = changelog_db_open;

        changelog.on_bi.bi_op_add = changelog_delmod;
        changelog.on_bi.bi_op_delete = changelog_delmod;
        changelog.on_bi.bi_op_modify = changelog_delmod;
        changelog.on_bi.bi_op_modrdn = changelog_delmod;
        changelog.on_bi.bi_op_abandon = changelog_cancel;
        changelog.on_bi.bi_op_cancel = changelog_cancel;
        
	changelog.on_response = changelog_response;

	changelog.on_bi.bi_cf_ocs = clog_cf_ocs;

	/* changelog schema integration */
	for ( i=0; clattrs[i].at; i++ ) {
		int code;

                code = register_at( clattrs[i].at, clattrs[i].ad, 0 );
                if ( code ) {
                        Debug( LDAP_DEBUG_ANY,
                                "changelog_init: register_at failed\n", 0, 0, 0 );
                        return -1;
                }
        }
	for ( i=0; clocs[i].ot; i++ ) {
		int code;

                code = register_oc( clocs[i].ot, clocs[i].oc, 0 );
                if ( code ) {
                        Debug( LDAP_DEBUG_ANY,
                                "changelog_init: register_oc failed\n", 0, 0, 0 );
                        return -1;
                }
        }
        
        rc = config_register_schema( clog_cf_attrs, clog_cf_ocs );
        if ( rc ) return rc;

        nullsc.sc_response = slap_null_cb;

        ldap_pvt_thread_mutex_init( &changelog_mutex );
        ldap_pvt_thread_mutex_init( &changenum_mutex );
        
	return(overlay_register(&changelog));
}

#if SLAPD_OVER_CHANGELOG == SLAPD_MOD_DYNAMIC
int init_module( int argc, char *argv[] )
{
        return changelog_initialize();
}
#endif
        
#endif /* SLAPD_OVER_CHANGELOG */
