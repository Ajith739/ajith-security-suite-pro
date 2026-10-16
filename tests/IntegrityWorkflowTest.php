<?php
// phpcs:ignoreFile -- Development-only real database and filesystem regressions.
use PHPUnit\Framework\TestCase;

final class IntegrityWorkflowTest extends TestCase {
    private $root;
    private $artifacts;
    private $checksumKey;
    private $checksums;
    private $enumerationFilter;

    protected function setUp(): void {
        global $wpdb, $wp_version;
        $wpdb->query('START TRANSACTION');
        $this->root = WP_PLUGIN_DIR . '/gwqsh-workflow-' . bin2hex(random_bytes(6));
        mkdir($this->root);
        // Exercise the real engine against this test's isolated filesystem scope.
        $this->enumerationFilter = function() { return array($this->root, GWQSH_Guardian::root()); };
        add_filter('gwqsh_scan_enumeration_roots', $this->enumerationFilter);
        $this->artifacts = glob(GWQSH_Quarantine_Manager::quarantine_dir() . '/*') ?: array();
        $this->checksumKey = 'gwqsh_checksums_' . md5($wp_version . '|' . get_locale());
        $this->checksums = get_transient($this->checksumKey);
        GWQSH_Scan_Engine::clear('gwqsh_scan_progress');
        GWQSH_Scan_Engine::save('gwqsh_file_baseline', array());
        set_transient($this->checksumKey, array('index.php' => md5_file(ABSPATH . 'index.php')), 60);
    }

    protected function tearDown(): void {
        remove_filter('gwqsh_scan_enumeration_roots', $this->enumerationFilter);
        global $wpdb;
        foreach (array_diff(glob(GWQSH_Quarantine_Manager::quarantine_dir() . '/*') ?: array(), $this->artifacts) as $file) {
            if (is_file($file) || is_link($file)) unlink($file);
        }
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($this->root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST) as $file) {
            $file->isDir() && !$file->isLink() ? rmdir($file->getPathname()) : unlink($file->getPathname());
        }
        rmdir($this->root);
        $wpdb->query('ROLLBACK');
        wp_cache_flush();
        false === $this->checksums ? delete_transient($this->checksumKey) : set_transient($this->checksumKey, $this->checksums, WEEK_IN_SECONDS);
    }

    private function finding($file, $status = 'Modified', $score = 0) {
        global $wpdb;
        $label = GWQSH_Scan_Engine::label($file);
        GWQSH_Scan_Engine::finding($label, 'Plugin', $status, 'Sanitized workflow fixture', array('hash' => hash_file('sha256', $file), 'score' => $score, 'severity' => $score >= 80 ? 'Critical' : 'Low', 'component' => 'plugin'));
        return (int) $wpdb->get_var($wpdb->prepare('SELECT id FROM ' . $wpdb->prefix . 'gwqsh_scan_results WHERE file_path=%s AND is_resolved=0', $label));
    }

    private function baseline($file) {
        $label = GWQSH_Scan_Engine::label($file);
        GWQSH_Scan_Engine::save('gwqsh_file_baseline', array($label => array('hash' => hash_file('sha256', $file), 'scope' => 'Plugin', 'size' => filesize($file), 'mtime' => filemtime($file))));
        return $label;
    }

    private function scan() {
        GWQSH_Scan_Engine::clear('gwqsh_scan_progress');
        do { $result = GWQSH_Scan_Engine::run(); $this->assertIsArray($result); } while (!empty($result['pending']));
        return $result;
    }

    public function test_readonly_folder_retries_keep_one_backup_until_isolation_succeeds() {
        if (PHP_OS_FAMILY === 'Windows') $this->markTestSkipped('POSIX permission semantics are unavailable on Windows.');
        $dir=$this->root.'/readonly';mkdir($dir,0700);$file=$dir.'/fixture.php';file_put_contents($file,"<?php\n// permission regression\nreturn;\n");
        $hash=hash_file('sha256',$file);$label=$this->baseline($file);$id=$this->finding($file);chmod($dir,0500);
        try {
            $artifact=null;
            for($i=0;$i<3;$i++) {
                $r=GWQSH_Quarantine_Manager::quarantine_by_finding($id);$this->assertInstanceOf(WP_Error::class,$r);
                $copies=array_values(array_filter(GWQSH_Quarantine_Manager::list_quarantined(),fn($r)=>GWQSH_Quarantine_Manager::path_key($r['original'])===GWQSH_Quarantine_Manager::path_key($label)));
                $this->assertCount(1,$copies);$this->assertTrue($copies[0]['isolation_failed']);
                $this->assertSame($hash,hash_file('sha256',$file));
                $artifact=$copies[0]['id'];
            }
            $this->assertTrue(GWQSH_Quarantine_Manager::delete_quarantined($artifact));
            $this->assertSame(1,GWQSH_File_Integrity::get_scan_issues_paged(array('search'=>$label))['total'],'Deleting a failed-isolation backup must not resolve the still-live original');
            // Once directory permissions allow deletion, original isolation succeeds.
            chmod($dir,0700);$q=GWQSH_Quarantine_Manager::quarantine_by_finding($id);$this->assertIsArray($q);$this->assertFileDoesNotExist($file);
        }finally{chmod($dir,0700);}
    }

    public function test_recreated_identical_bytes_and_failed_removal_backup_reuse_one_artifact() {
        global $wpdb;
        $file = $this->root . '/retry.php'; $content = "<?php\n// retry fixture\nreturn;\n";
        file_put_contents($file, $content); $this->baseline($file); $id = $this->finding($file);
        $backup = GWQSH_Quarantine_Manager::quarantine_by_finding($id, true);
        $this->assertIsArray($backup);
        $q = GWQSH_Quarantine_Manager::quarantine_by_finding($id);
        $this->assertSame($backup['artifact_id'], $q['artifact_id']);
        for ($i=0; $i<3; $i++) {
            file_put_contents($file, $content); $id = $this->finding($file);
            $again = GWQSH_Quarantine_Manager::quarantine_by_finding($id);
            $this->assertSame($q['artifact_id'], $again['artifact_id']);
            $this->assertFileDoesNotExist($file);
        }
        $this->assertTrue(GWQSH_Quarantine_Manager::delete_quarantined($q['artifact_id']));
        $this->scan();
        $this->assertSame(0, GWQSH_File_Integrity::get_scan_issues_paged(array('search'=>GWQSH_Scan_Engine::label($this->root . '/index.php') ?: basename($this->root)))['total']);
    }

    public function test_review_500_findings_uses_one_update_and_never_accepts_contents() {
        global $wpdb;
        $ids=[];
        for($i=0;$i<500;$i++) { $wpdb->insert($wpdb->prefix.'gwqsh_scan_results',array('file_path'=>'/wp-content/plugins/'.basename($this->root).'/'.$i.'.php','file_type'=>'Plugin','status'=>'Modified','details'=>'bulk review fixture','is_resolved'=>0,'detected_at'=>current_time('mysql')));$ids[]=(int)$wpdb->insert_id; }
        $baseline = GWQSH_Scan_Engine::load('gwqsh_file_baseline'); $queries=$wpdb->num_queries;
        $r=GWQSH_File_Integrity::review_findings($ids);
        $this->assertSame(1, $wpdb->num_queries-$queries);
        $this->assertSame(500,$r['reviewed']);
        $this->assertSame(0,$r['skipped']);
        $this->assertSame($baseline,GWQSH_Scan_Engine::load('gwqsh_file_baseline'));
        $this->assertSame(500,GWQSH_File_Integrity::review_findings($ids)['skipped']);
        $this->assertInstanceOf(WP_Error::class,GWQSH_File_Integrity::review_findings(array_merge($ids,array(2147483647))));
    }

    public function test_acceptance_retains_real_old_text_after_quarantine_is_cleared() {
        $file=$this->root.'/snapshot.php'; $old="<?php\n// unique trusted " . basename($this->root) . "\nreturn;\n";
        file_put_contents($file,$old); $id=$this->finding($file);
        $this->assertTrue(GWQSH_Quarantine_Manager::accept_current($id));
        $copy=GWQSH_Quarantine_Manager::trusted_copy(GWQSH_Scan_Engine::label($file));
        $this->assertIsArray($copy); $this->assertSame($old,file_get_contents($copy['source']));
        file_put_contents($file,str_replace('unique trusted','unique changed',$old)); $this->finding($file);
        $diff=GWQSH_File_Integrity::get_file_diff(GWQSH_Scan_Engine::label($file));
        $this->assertStringContainsString('unique trusted',$diff); $this->assertStringContainsString('unique changed',$diff);
        $this->assertStringContainsString('Show complete old / new file',$diff);
    }

    public function test_failed_removal_history_write_does_not_delete_evidence() {
        $file=$this->root.'/history.php';file_put_contents($file,"<?php\nreturn;\n");$this->baseline($file);
        $q=GWQSH_Quarantine_Manager::quarantine_by_finding($this->finding($file));
        $deny=static fn($new,$old)=>$old; add_filter('pre_update_option_gwqsh_intentional_removals',$deny,10,2);
        try { $r=GWQSH_Quarantine_Manager::delete_quarantined($q['artifact_id']); $this->assertInstanceOf(WP_Error::class,$r); $this->assertFileExists(GWQSH_Quarantine_Manager::quarantine_dir().'/'.$q['artifact_id'].'.quarantine'); $this->assertArrayHasKey($q['artifact_id'].'.quarantine',GWQSH_Quarantine_Manager::list_quarantined()); }
        finally { remove_filter('pre_update_option_gwqsh_intentional_removals',$deny,10); }
    }

    public function test_repeated_quarantine_and_stale_findings_after_permanent_delete() {
        global $wpdb;
        $file = $this->root . '/repeat.php';
        file_put_contents($file, "<?php\n// trusted fixture\nreturn;\n");
        $label = $this->baseline($file);
        $id = $this->finding($file);
        $row = $wpdb->get_row($wpdb->prepare('SELECT * FROM ' . $wpdb->prefix . 'gwqsh_scan_results WHERE id=%d', $id), ARRAY_A);
        unset($row['id']); $wpdb->insert($wpdb->prefix . 'gwqsh_scan_results', $row);
        $duplicate = (int) $wpdb->insert_id;
        $before = count(GWQSH_Quarantine_Manager::list_quarantined());
        $q = GWQSH_Quarantine_Manager::quarantine_by_finding($id);
        $this->assertIsArray($q);
        for ($i = 0; $i < 3; $i++) {
            $again = GWQSH_Quarantine_Manager::quarantine_by_finding($i === 2 ? $duplicate : $id);
            $this->assertIsArray($again);
            $this->assertSame($q['artifact_id'], $again['artifact_id']);
        }
        $this->assertCount($before + 1, GWQSH_Quarantine_Manager::list_quarantined());
        $this->assertSame(0, GWQSH_File_Integrity::get_scan_issues_paged(array('search' => $label))['total']);
        // Simulate a legacy unresolved row surviving quarantine.
        $wpdb->insert($wpdb->prefix . 'gwqsh_scan_results', $row);
        $this->assertTrue(GWQSH_Quarantine_Manager::delete_quarantined($q['artifact_id']));
        $this->scan();
        $this->assertSame(0, GWQSH_File_Integrity::get_scan_issues_paged(array('search' => $label))['total']);
        // A recreated live file must still be inspected, even when identical to removed bytes.
        file_put_contents($file, "<?php\n// changed fixture\nreturn;\n");
        $this->scan();
        $this->assertSame(1, GWQSH_File_Integrity::get_scan_issues_paged(array('search' => $label))['total']);
    }

    public function test_complete_diff_includes_late_changes_insertions_deletions_and_escaped_source() {
        $old = implode("\n", array_map(fn($i) => "line $i", range(1, 1800))) . "\n";
        $new = str_replace("line 1700\n", "inserted late <script>bad()</script>\nsecond inserted\n", $old);
        $new = str_replace("line 1790\n", '', $new);
        $diff = GWQSH_File_Integrity::render_complete_diff($old, $new);
        $this->assertStringContainsString('line 1800', $diff);
        $this->assertStringContainsString('inserted late &lt;script&gt;', $diff);
        $this->assertStringNotContainsString('<script>', $diff);
        $this->assertStringContainsString('2 added lines · 2 removed lines', $diff);
        $this->assertStringContainsString('class="old-ln">1700', $diff);
        $this->assertStringContainsString('class="new-ln">1701', $diff);
        $this->assertStringNotContainsString('Line endings differ', GWQSH_File_Integrity::render_complete_diff("one\r\n", "one\r\ntwo\r\n"));
        $this->assertStringContainsString('old CRLF → new LF', GWQSH_File_Integrity::render_complete_diff("one\r\n", "one\n"));
    }

    public function test_1100_findings_all_page_sizes_exact_ids_limits_offsets_filters_and_clamping() {
        global $wpdb;
        $marker = 'pagination-' . bin2hex(random_bytes(6));
        $ids = array();
        for ($i = 0; $i < 1100; $i++) {
            $wpdb->insert($wpdb->prefix . 'gwqsh_scan_results', array('file_path' => '/wp-content/plugins/' . $marker . '/' . sprintf('%04d', $i) . '.php', 'file_type' => 'Plugin', 'status' => $i % 2 ? 'Modified' : 'Suspicious', 'details' => $marker, 'detected_at' => '2026-10-04 12:00:00', 'is_resolved' => 0, 'evidence' => wp_json_encode(array('score' => $i % 100, 'severity' => $i % 2 ? 'Low' : 'High', 'component' => 'plugin'))));
            $ids[] = (int) $wpdb->insert_id;
        }
        $queries = array();
        $capture = static function($sql) use (&$queries) { $queries[] = $sql; return $sql; };
        add_filter('query', $capture);
        try {
            foreach (array(5,10,20,25,30,50,100,250,500) as $size) {
                $seen = array();
                $pages = (int) ceil(1100 / $size);
                for ($page = 1; $page <= $pages; $page++) {
                    $queries = array();
                    $result = GWQSH_File_Integrity::get_scan_issues_paged(array('search' => $marker, 'sort' => 'date', 'order' => 'ASC', 'per_page' => $size, 'page' => $page));
                    $this->assertSame(1100, $result['total']); $this->assertSame($pages, $result['pages']); $this->assertSame($page, $result['page']);
                    $actual = array_map('intval', array_column($result['items'], 'id'));
                    $this->assertSame(array_slice($ids, ($page - 1) * $size, $size), $actual);
                    $this->assertStringContainsString('LIMIT ' . $size . ' OFFSET ' . (($page - 1) * $size), implode("\n", $queries));
                    $seen = array_merge($seen, $actual);
                }
                $this->assertSame($ids, $seen); $this->assertCount(1100, array_unique($seen));
                $last = GWQSH_File_Integrity::get_scan_issues_paged(array('search' => $marker, 'per_page' => $size, 'page' => 9999));
                $this->assertSame($pages, $last['page']);
            }
            $filtered = GWQSH_File_Integrity::get_scan_issues_paged(array('search' => $marker, 'status' => 'Modified', 'type' => 'Plugin', 'severity' => 'Low', 'per_page' => 100, 'page' => 3, 'sort' => 'score', 'order' => 'ASC'));
            $this->assertSame(550, $filtered['total']); $this->assertCount(100, $filtered['items']);
            $last = GWQSH_File_Integrity::get_scan_issues_paged(array('search' => $marker, 'per_page' => 500, 'page' => 3));
            foreach ($last['items'] as $row) $wpdb->update($wpdb->prefix . 'gwqsh_scan_results', array('is_resolved' => 1), array('id' => $row['id']));
            $this->assertSame(2, GWQSH_File_Integrity::get_scan_issues_paged(array('search' => $marker, 'per_page' => 500, 'page' => 3))['page']);
            $empty = GWQSH_File_Integrity::get_scan_issues_paged(array('search' => $marker . '-absent', 'page' => 99));
            $this->assertSame(1, $empty['page']); $this->assertSame(0, $empty['total']);
            foreach (array('path','type','status','severity','score','modified','date', 'path; DROP TABLE foo') as $sort) {
                $this->assertCount(20, GWQSH_File_Integrity::get_scan_issues_paged(array('search' => $marker, 'sort' => $sort))['items']);
            }
        } finally { remove_filter('query', $capture); }
    }

    public function test_quarantine_full_rescan_restore_recreation_and_permanent_delete() {
        $file = $this->root . '/fixture.php';
        file_put_contents($file, file_get_contents(__DIR__ . '/fixtures/webshell.fixture'));
        $label = $this->baseline($file);
        $id = $this->finding($file, 'Suspicious', 90);
        $quarantine = GWQSH_Quarantine_Manager::quarantine_by_finding($id);
        $this->assertIsArray($quarantine); $this->assertFileDoesNotExist($file);
        $this->assertSame('Quarantined', GWQSH_Quarantine_Manager::absence_state($label));
        $rescan = $this->scan();
        $this->assertSame(0, $rescan['missing']);
        $this->assertSame(0, GWQSH_File_Integrity::get_scan_issues_paged(array('search' => $label))['total']);
        $this->assertSame('Quarantined', GWQSH_Quarantine_Manager::list_quarantined()[$quarantine['artifact_id'] . '.quarantine']['status']);
        $this->assertIsArray(GWQSH_Quarantine_Manager::restore_quarantined($quarantine['artifact_id']));
        $this->assertFalse(GWQSH_Quarantine_Manager::is_path_quarantined($label));
        $this->scan();
        $issues = GWQSH_File_Integrity::get_scan_issues_paged(array('search' => $label));
        $this->assertSame('Suspicious', $issues['items'][0]['st']);
        $quarantine = GWQSH_Quarantine_Manager::quarantine_by_finding($issues['items'][0]['id']);
        // Recreation while an active artifact exists is inspected, never suppressed.
        file_put_contents($file, file_get_contents(__DIR__ . '/fixtures/webshell.fixture'));
        $this->assertFalse(GWQSH_Quarantine_Manager::is_path_quarantined($label));
        $this->scan();
        $issues = GWQSH_File_Integrity::get_scan_issues_paged(array('search' => $label));
        $this->assertSame('Critical', $issues['items'][0]['severity']);
        unlink($file);
        $this->assertTrue(GWQSH_Quarantine_Manager::delete_quarantined($quarantine['artifact_id']));
        $this->assertSame('Removed', GWQSH_Quarantine_Manager::absence_state($label, hash_file('sha256', __DIR__ . '/fixtures/webshell.fixture')));
        // Existing recreation finding is reviewed; no new Missing may be added.
        global $wpdb;
        $wpdb->update($wpdb->prefix . 'gwqsh_scan_results', array('is_resolved' => 1), array('id' => $issues['items'][0]['id']));
        $this->scan();
        $this->assertSame(0, GWQSH_File_Integrity::get_scan_issues_paged(array('search' => $label, 'status' => 'Missing'))['total']);
        file_put_contents($file, file_get_contents(__DIR__ . '/fixtures/webshell.fixture'));
        $this->scan();
        $this->assertSame('Critical', GWQSH_File_Integrity::get_scan_issues_paged(array('search' => $label))['items'][0]['severity']);
    }

    public function test_modified_old_new_hash_verification_and_critical_rejection() {
        $file = $this->root . '/safe.php'; $old = "<?php\n// Trusted OLD\nreturn;\n"; $new = "<?php\n// Safe NEW <script>alert(1)</script>\nreturn;\n";
        file_put_contents($file, $old); $label = $this->baseline($file);
        $id = $this->finding($file);
        $backup = GWQSH_Quarantine_Manager::quarantine_by_finding($id, true); $this->assertIsArray($backup);
        file_put_contents($file, $new);
        $this->scan();
        $row = GWQSH_File_Integrity::get_scan_issues_paged(array('search' => $label))['items'][0];
        $this->assertSame('Modified', $row['st']);
        $diff = GWQSH_File_Integrity::get_file_diff($label);
        $this->assertStringContainsString('&lt;script&gt;', $diff); $this->assertStringNotContainsString('<script>', $diff);
        $this->assertTrue(GWQSH_Quarantine_Manager::restore_trusted($row['id']));
        $this->assertSame($old, file_get_contents($file));
        $hashes = array_column(GWQSH_Quarantine_Manager::list_quarantined(), 'hash'); $this->assertContains(hash('sha256', $new), $hashes);
        file_put_contents($file, $new); $id = $this->finding($file);
        $this->assertTrue(GWQSH_Quarantine_Manager::accept_current($id));
        $this->assertSame(hash('sha256', $new), GWQSH_Scan_Engine::load('gwqsh_file_baseline')[$label]['hash']);
        file_put_contents($file, file_get_contents(__DIR__ . '/fixtures/webshell.fixture'));
        // Fake low severity does not avoid fresh analysis.
        $id = $this->finding($file);
        $this->assertSame('critical_malware_cannot_accept', GWQSH_Quarantine_Manager::accept_current($id)->get_error_code());
        $metadata = get_option(GWQSH_Quarantine_Manager::METADATA_OPTION);
        $trustedCopy = GWQSH_Quarantine_Manager::trusted_copy($label);
        $this->assertIsArray($trustedCopy);
        $name = basename($trustedCopy['source']);
        file_put_contents(GWQSH_Quarantine_Manager::quarantine_dir() . '/' . $name, 'corrupted');
        foreach (GWQSH_Quarantine_Manager::list_quarantined() as $copy) {
            if ($copy['hash'] === $trustedCopy['hash']) file_put_contents(GWQSH_Quarantine_Manager::quarantine_dir() . '/' . $copy['file'], 'corrupted');
        }
        $this->assertNull(GWQSH_Quarantine_Manager::trusted_copy($label));
        $this->assertInstanceOf(WP_Error::class, GWQSH_Quarantine_Manager::restore_trusted($id));
    }

    public function test_deleted_unexpected_root_file_does_not_return_as_missing() {
        $file = ABSPATH . 'gwqsh-workflow-' . bin2hex(random_bytes(5)) . '.php';
        try {
            file_put_contents($file, "<?php\n// Inert unexpected root file\nreturn;\n");
            $label = $this->baseline($file);
            $q = GWQSH_Quarantine_Manager::quarantine_by_finding($this->finding($file));
            $this->assertIsArray($q);
            $this->assertTrue(GWQSH_Quarantine_Manager::delete_quarantined($q['artifact_id']));
            $this->scan();
            $this->assertSame(0, GWQSH_File_Integrity::get_scan_issues_paged(array('search' => $label))['total']);
            $this->assertFileDoesNotExist($file);
        } finally { if (file_exists($file)) unlink($file); }
    }

    public function test_deleted_mu_evidence_retains_owned_stub_without_rescan_alerts() {
        $file = GWQSH_Guardian::root() . '/z-gwqsh-workflow-' . bin2hex(random_bytes(5)) . '.php';
        try {
            file_put_contents($file, "<?php\n// Inert MU regression fixture\nreturn;\n");
            $hash = hash_file('sha256', $file);
            $label = $this->baseline($file);
            $q = GWQSH_Quarantine_Manager::quarantine_by_finding($this->finding($file));
            $this->assertIsArray($q);
            $this->assertTrue(GWQSH_Quarantine_Manager::delete_quarantined($q['artifact_id']));
            $this->assertTrue(GWQSH_Quarantine_Manager::is_owned_sentinel($label));
            $this->assertSame('Removed', GWQSH_Quarantine_Manager::absence_state($label, $hash));
            $this->scan();
            $this->assertSame(0, GWQSH_File_Integrity::get_scan_issues_paged(array('search' => $label))['total']);
        } finally { if (file_exists($file)) unlink($file); }
    }

    public function test_mu_sentinel_full_rescan_and_replacement() {
        $file = GWQSH_Guardian::root() . '/z-gwqsh-workflow-' . bin2hex(random_bytes(5)) . '.php';
        try {
            file_put_contents($file, file_get_contents(__DIR__ . '/fixtures/webshell.fixture'));
            $label = $this->baseline($file); $id = $this->finding($file, 'Suspicious', 90);
            $q = GWQSH_Quarantine_Manager::quarantine_by_finding($id); $this->assertIsArray($q);
            $this->assertTrue(GWQSH_Quarantine_Manager::is_owned_sentinel($label));
            $stale = $this->finding($file); // A legacy row recorded the harmless blocking stub.
            $again = GWQSH_Quarantine_Manager::quarantine_by_finding($stale);
            $this->assertIsArray($again); $this->assertSame($q['artifact_id'], $again['artifact_id']);
            $beforeScan = GWQSH_File_Integrity::get_scan_issues_paged(array('search' => $label));
            $this->assertSame(0, $beforeScan['total'], json_encode($beforeScan['items']));
            $this->scan(); $this->assertSame(0, GWQSH_File_Integrity::get_scan_issues_paged(array('search' => $label))['total']);
            file_put_contents($file, file_get_contents(__DIR__ . '/fixtures/webshell.fixture'));
            $this->assertFalse(GWQSH_Quarantine_Manager::is_owned_sentinel($label));
            $this->scan(); $this->assertSame('Critical', GWQSH_File_Integrity::get_scan_issues_paged(array('search' => $label))['items'][0]['severity']);
            $this->assertSame('target_exists', GWQSH_Quarantine_Manager::restore_quarantined($q['artifact_id'])->get_error_code());
        } finally { if (file_exists($file)) unlink($file); }
    }

    public function test_clear_all_partial_failure_never_deletes_live_files_or_loses_failed_metadata() {
        if (PHP_OS_FAMILY === 'Windows') $this->markTestSkipped('This regression requires symlink creation privileges.');
        update_option(GWQSH_Quarantine_Manager::METADATA_OPTION, array(), false);
        $file = $this->root . '/large.txt'; file_put_contents($file, str_repeat('bounded harmless data ', 300000));
        $hash = hash_file('sha256', $file); $id = $this->finding($file);
        $q = GWQSH_Quarantine_Manager::quarantine_by_finding($id); $this->assertIsArray($q);
        $name = $q['artifact_id'] . '.quarantine';
        $this->assertSame($hash, hash_file('sha256', GWQSH_Quarantine_Manager::quarantine_dir() . '/' . $name));
        $live = $this->root . '/live.txt'; file_put_contents($live, 'keep live');
        $bad = bin2hex(random_bytes(16)) . '.quarantine'; symlink($live, GWQSH_Quarantine_Manager::quarantine_dir() . '/' . $bad);
        $meta = get_option(GWQSH_Quarantine_Manager::METADATA_OPTION); $meta[$bad] = array('id' => substr($bad,0,32), 'original' => GWQSH_Scan_Engine::label($live), 'hash' => hash_file('sha256',$live), 'reason' => 'scan_quarantine'); update_option(GWQSH_Quarantine_Manager::METADATA_OPTION,$meta,false);
        $result = GWQSH_Quarantine_Manager::clear_all_quarantine();
        $this->assertSame(1,$result['deleted']); $this->assertSame(1,$result['failed']); $this->assertCount(1,$result['errors']);
        $this->assertArrayHasKey($bad,get_option(GWQSH_Quarantine_Manager::METADATA_OPTION));
        $this->assertFileDoesNotExist(GWQSH_Quarantine_Manager::quarantine_dir() . '/' . $name);
        $this->assertFileDoesNotExist(GWQSH_Quarantine_Manager::quarantine_dir() . '/' . $q['artifact_id'] . '.json');
        $this->assertSame('keep live', file_get_contents($live));
        $this->assertInstanceOf(WP_Error::class, GWQSH_Quarantine_Manager::delete_quarantined('../../wp-config.php'));
    }

    public function test_damaged_evidence_orphans_and_hash_mismatch_never_become_trusted() {
        $file = $this->root . '/damaged.php'; file_put_contents($file,"<?php\nreturn;\n");
        $label = $this->baseline($file); $id = $this->finding($file);
        $q = GWQSH_Quarantine_Manager::quarantine_by_finding($id); $this->assertIsArray($q);
        $artifact = GWQSH_Quarantine_Manager::quarantine_dir() . '/' . $q['artifact_id'] . '.quarantine';
        file_put_contents($artifact,'tampered bytes');
        $this->assertSame('hash_mismatch',GWQSH_Quarantine_Manager::restore_quarantined($q['artifact_id'])->get_error_code());
        $this->assertFileDoesNotExist($file);
        unlink($artifact);
        $this->assertSame('Damaged',GWQSH_Quarantine_Manager::absence_state($label));
        $scan = $this->scan(); $this->assertContains('quarantine_evidence_missing',$scan['coverage']);
        $this->assertSame(0,$scan['missing']);
        $this->assertSame('Damaged / missing evidence',GWQSH_Quarantine_Manager::list_quarantined()[$q['artifact_id'].'.quarantine']['status']);
        $orphan = bin2hex(random_bytes(16)) . '.quarantine';
        file_put_contents(GWQSH_Quarantine_Manager::quarantine_dir() . '/' . $orphan,'orphaned owned-name fixture');
        GWQSH_Quarantine_Manager::reconcile();
        $this->assertContains($orphan,get_option('gwqsh_quarantine_orphans'));
        $this->assertArrayNotHasKey($orphan,GWQSH_Quarantine_Manager::list_quarantined());
        $this->assertSame('quarantine_record_missing',GWQSH_Quarantine_Manager::delete_quarantined($orphan)->get_error_code());
    }

    public function test_restore_cleanup_failure_preserves_verified_live_file_and_owned_metadata() {
        if (PHP_OS_FAMILY === 'Windows') $this->markTestSkipped('POSIX permission semantics are unavailable on Windows.');
        $file = $this->root . '/cleanup.php'; file_put_contents($file,"<?php\nreturn;\n");
        $id = $this->finding($file); $hash = hash_file('sha256',$file);
        $q = GWQSH_Quarantine_Manager::quarantine_by_finding($id); $this->assertIsArray($q);
        $dir = GWQSH_Quarantine_Manager::quarantine_dir();
        $readonly = static function($value) use ($dir) { chmod($dir,0500); return $value; };
        add_filter('pre_update_option_gwqsh_intentional_removals',$readonly);
        try {
            $result = GWQSH_Quarantine_Manager::restore_quarantined($q['artifact_id']);
            $this->assertInstanceOf(WP_Error::class,$result);
            $this->assertSame('restore_cleanup_failed',$result->get_error_code());
            $this->assertSame($hash,hash_file('sha256',$file));
            $this->assertArrayHasKey($q['artifact_id'].'.quarantine',get_option(GWQSH_Quarantine_Manager::METADATA_OPTION));
        } finally { remove_filter('pre_update_option_gwqsh_intentional_removals',$readonly); chmod($dir,0700); }
    }

    public function test_missing_parent_paths_and_symlink_escapes_are_rejected() {
        $label = '/wp-content/plugins/' . basename($this->root) . '/new/deep/file.txt';
        $this->assertSame(wp_normalize_path($this->root . '/new/deep/file.txt'), wp_normalize_path(GWQSH_Path_Guard::validate($label, false)['canonical']));
        if (PHP_OS_FAMILY === 'Windows') $this->markTestSkipped('Remaining symlink escape assertions require symlink privileges.');
        symlink($this->root, $this->root . '/link');
        $this->assertNull(GWQSH_Path_Guard::validate('/wp-content/plugins/' . basename($this->root) . '/link/file.txt', false));
        $this->assertNull(GWQSH_Path_Guard::validate('/@plugin/../../outside', false));
        $this->assertSame('wp-content/mu-plugins/safe.php', GWQSH_Quarantine_Manager::display_path('/@mu/safe.php'));
    }
}
